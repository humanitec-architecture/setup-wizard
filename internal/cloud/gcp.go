package cloud

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/humanitec/humanitec-go-autogen/client"

	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/humanitec/humctl-wizard/internal/utils"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	container "google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iam "google.golang.org/api/iam/v1"
	k8s_rbac "k8s.io/api/rbac/v1"
	k8s_apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	serviceusagepb "cloud.google.com/go/serviceusage/apiv1/serviceusagepb"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	RandomPostfixLength                                   = 10
	WorkloadIdentityPoolBaseName                          = "humanitec-wif-pool"
	WorkloadIdentityPoolDescription                       = "Workload Identity Pool to access Resource from Humanitec"
	OIDCWorkloadIdentityPoolProviderBaseName              = "humanitec-wif"
	OIDCWorkloadIdentityPoolProviderIssuerURI             = "https://idtoken.humanitec.io"
	OIDCWorkloadIdentityPoolProviderDescription           = "Workload Identity Pool Provider OIDC"
	OIDCWorkloadIdentityPoolProviderAttributeMappingKey   = "google.subject"
	OIDCWorkloadIdentityPoolProviderAttributeMappingValue = "assertion.sub"
	HumanitecServiceAccountName                           = "humanitec-sa"
	HumanitecServiceAccountDescription                    = "Service Account to be used by the Humanitec Cloud Account"
	HumanitecServiceAccountPolicyBindingRole              = "iam.workloadIdentityUser"
	HumanitecCloudAccountGCPIdentityType                  = "gcp-identity"
	IAMCustomRoleBaseName                                 = "HumanitecGKEAccess"
	IAMCustomRoleDescription                              = "GKE access least privilege to deploy via Humanitec"
	K8sClusterRoleBaseName                                = "humanitec-deploy-access"
	K8sClusterRoleBindingBaseName                         = "humanitec-deploy-access"
	IAMSecretManagerRoleBaseName                          = "SecretmanagerReadWrite"
	IAMSecretManagerRoleDescription                       = "Can create new and update existing secrets and read them"
)

type gcpProvider struct {
	id string

	credentials       *google.Credentials
	humanitecPlatform *platform.HumanitecPlatform

	k8sClient   *kubernetes.Clientset
	clusterInfo *container.Cluster
}

// NewGCPProvider retrieves the Google Application Default Credentials.
// See: https://cloud.google.com/docs/authentication/application-default-credentials#personal
// User should select which project use. Secret Manager API should be enabled in that project if the Operator will be chosen as deployment mode.
// The cluster where the operator will eventually run, should have workload_identity enabled, see: https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity.
// The user running the script need this set of permissions:
// - roles/iam.workloadIdentityPoolAdmin
// - roles/iam.serviceAccountAdmin
// - roles/container.admin
// - roles/iam.roleAdmin
// - roles/serviceusage.serviceUsageViewer
func NewGCPProvider(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (Provider, error) {
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("failed to load default gpc credentials: %w", err)
	}

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create a resource manager service: %w", err)
	}

	projects, err := crmService.Projects.List().Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	var projectsSelection = make([]string, 0, len(projects.Projects))
	var projectsInfo = map[string]*cloudresourcemanager.Project{}
	for _, project := range projects.Projects {
		projectsSelection = append(projectsSelection, project.ProjectId)
		projectsInfo[project.ProjectId] = project
	}

	if storedProject := session.State.GCPProvider.GPCProject.ProjectID; storedProject != "" {
		message.Info("Using project from previous session: project id '%s'", storedProject)
	} else {
		projectID, err := message.Select("Select a GCP project", projectsSelection)
		if err != nil {
			return nil, fmt.Errorf("failed to select a GCP project: %w", err)
		}

		session.State.GCPProvider.GPCProject.ProjectID = projectID
		session.State.GCPProvider.GPCProject.ProjectNumber = projectsInfo[projectID].ProjectNumber
	}

	if session.State.GCPProvider.GCPResourcesPostfix == "" {
		session.State.GCPProvider.GCPResourcesPostfix = randomString(RandomPostfixLength)
	}

	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return &gcpProvider{
		id:                "gcp",
		credentials:       creds,
		humanitecPlatform: humanitecPlatform,
	}, nil
}

func (p *gcpProvider) GetCallingUserId(ctx context.Context) (string, error) {
	client, err := google.DefaultClient(ctx, oauth2.UserinfoEmailScope)
	if err != nil {
		return "", fmt.Errorf("failed to load default gpc credentials: %w", err)
	}

	oauth2Service, err := oauth2.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return "", fmt.Errorf("failed to create oauth2 service: %w", err)
	}

	userInfo, err := oauth2.NewUserinfoV2MeService(oauth2Service).Get().Do()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %w", err)
	}

	return userInfo.Id, nil
}

func (p *gcpProvider) SetupProvider(ctx context.Context) error {
	return nil
}

// Actions taken from: https://developer.humanitec.com/platform-orchestrator/security/cloud-accounts/gcp/#gcp-service-account-impersonation
func (p *gcpProvider) CreateCloudIdentity(ctx context.Context, cloudAccountId, cloudAccountName string) (string, error) {
	projectID := session.State.GCPProvider.GPCProject.ProjectID
	projectNumber := session.State.GCPProvider.GPCProject.ProjectNumber

	iamService, err := iam.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return "", fmt.Errorf("failed to create an IAM service for gcp: %w", err)
	}

	var wliPoolExists bool
	if storedWliPoolName := session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName; storedWliPoolName != "" {
		fullWlName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, storedWliPoolName)
		wliPool, err := iamService.Projects.Locations.WorkloadIdentityPools.Get(
			fullWlName,
		).Context(ctx).Do()

		if err != nil {
			if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to check Workload Identity Pool '%s' existence", storedWliPoolName)); !notFound {
				return "", parsedErr
			}
		} else if wliPool != nil && wliPool.State == "DELETED" {
			return "", fmt.Errorf("workload Identity Pool '%s' has been recently deleted, please restore it", storedWliPoolName)
		} else {
			wliPoolExists = true
			message.Info("Workload Identity Pool '%s' already exists: %s", storedWliPoolName, wliPool.Description)
		}
	}

	if !wliPoolExists {
		wliPoolName := WorkloadIdentityPoolBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		message.Info("Creating Workload Identity Pool: gcloud iam workload-identity-pools create %s --location=\"global\" --project %s",
			wliPoolName,
			projectID)
		if _, err := iamService.Projects.Locations.WorkloadIdentityPools.Create(
			fmt.Sprintf("projects/%s/locations/global", projectID),
			&iam.WorkloadIdentityPool{
				Description: WorkloadIdentityPoolDescription,
			},
		).WorkloadIdentityPoolId(wliPoolName).Context(ctx).Do(); err != nil {
			return "", fmt.Errorf("failed to create Workload Identity Pool '%s': %w", wliPoolName, err)
		}
		session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName = wliPoolName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Workload Identity Pool '%s' created.", wliPoolName)
	}

	wliPoolName := session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName
	var wliProviderExists bool
	if storedWliProviderName := session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName; storedWliProviderName != "" {
		fullWlpName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectID, wliPoolName, storedWliProviderName)
		wliProvider, err := iamService.Projects.Locations.WorkloadIdentityPools.Providers.Get(fullWlpName).Context(ctx).Do()

		if err != nil {
			if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to check Workload Identity Pool Provider '%s' existence", storedWliProviderName)); !notFound {
				return "", parsedErr
			}
		} else if wliProvider != nil && wliProvider.State == "DELETED" {
			return "", fmt.Errorf("workload Identity Pool Provider '%s' has been recently deleted, please restore it", storedWliProviderName)
		} else {
			wliProviderExists = true
			message.Info("Workload Identity Pool Provider '%s/%s' already exists: %s", wliPoolName, storedWliProviderName, wliProvider.Description)
		}
	}

	if !wliProviderExists {
		wliProviderName := OIDCWorkloadIdentityPoolProviderBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		message.Info("Creating OIDC Workload Identity Pool Provider: gcloud iam workload-identity-pools providers create-oidc %s --location=\"global\" --workload-identity-pool=\"%s\" --issuer-uri=\"%s\" --attribute-mapping=\"%s=%s\" --project=%s",
			wliProviderName,
			wliPoolName,
			OIDCWorkloadIdentityPoolProviderIssuerURI,
			OIDCWorkloadIdentityPoolProviderAttributeMappingKey,
			OIDCWorkloadIdentityPoolProviderAttributeMappingValue,
			projectID)
		if _, err := iamService.Projects.Locations.WorkloadIdentityPools.Providers.Create(
			fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, wliPoolName),
			&iam.WorkloadIdentityPoolProvider{
				Description: OIDCWorkloadIdentityPoolProviderDescription,
				Oidc: &iam.Oidc{
					IssuerUri: OIDCWorkloadIdentityPoolProviderIssuerURI,
				},
				AttributeMapping: map[string]string{OIDCWorkloadIdentityPoolProviderAttributeMappingKey: OIDCWorkloadIdentityPoolProviderAttributeMappingValue},
			},
		).WorkloadIdentityPoolProviderId(wliProviderName).Context(ctx).Do(); err != nil {
			return "", fmt.Errorf("failed to create Workload Identity Pool Provider '%s/%s': %w", wliPoolName, wliProviderName, err)
		}
		session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName = wliProviderName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Workload Identity Pool Provider '%s/%s' created", wliPoolName, wliProviderName)
	}

	var humServiceAccountExists bool
	if humStoredServiceAccount := session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountUniqueID; humStoredServiceAccount != "" {
		humSA, err := iamService.Projects.ServiceAccounts.Get(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, humStoredServiceAccount)).Context(ctx).Do()
		if err != nil {
			if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to check Service Account '%s' existence", humStoredServiceAccount)); !notFound {
				return "", parsedErr
			}
		} else {
			humServiceAccountExists = true
			message.Info("Service Account with unique ID '%s' already exists: %s", humStoredServiceAccount, humSA.Email)
		}
	}
	if !humServiceAccountExists {
		saName := HumanitecServiceAccountName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		var sa *iam.ServiceAccount
		message.Info("Creating GCP Service Account to be used by the Humanitec Cloud Account: gcloud iam service-accounts create %s --description=\"%s\" --display-name=\"%s\" --project=%s",
			saName,
			HumanitecServiceAccountDescription,
			saName,
			projectID)
		if sa, err = iamService.Projects.ServiceAccounts.Create(
			fmt.Sprintf("projects/%s", projectID),
			&iam.CreateServiceAccountRequest{
				AccountId: saName,
				ServiceAccount: &iam.ServiceAccount{
					Description: HumanitecServiceAccountDescription,
				},
			}).Context(ctx).Do(); err != nil {
			return "", fmt.Errorf("failed to create Service Account '%s': %w", saName, err)
		}
		session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountUniqueID = sa.UniqueId
		session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName = saName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Service Account '%s' created.", saName)
	}

	gcpServiceAccountEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName, projectID)
	gcpServiceAccountFullID := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, gcpServiceAccountEmail)
	policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy(gcpServiceAccountFullID).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve policy for '%s'", gcpServiceAccountFullID)
	}

	orgID := p.humanitecPlatform.OrganizationId
	iamPolicyBindingMember := fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/subject/%s/%s",
		projectNumber, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, orgID, cloudAccountId)
	var workloadIdentityUserBindingFound bool
	for _, binding := range policy.Bindings {
		if binding.Role == "roles/"+HumanitecServiceAccountPolicyBindingRole {
			if !slices.Contains(binding.Members, iamPolicyBindingMember) {
				binding.Members = append(binding.Members, iamPolicyBindingMember)
			}
			workloadIdentityUserBindingFound = true
		}
	}
	if !workloadIdentityUserBindingFound {
		policy.Bindings = append(policy.Bindings, &iam.Binding{
			Role:    "roles/" + HumanitecServiceAccountPolicyBindingRole,
			Members: []string{iamPolicyBindingMember},
		})
	}

	message.Info("Adding policy binding between the Service Account and the Workload Identitly Federation: gcloud iam service-accounts add-iam-policy-binding %s --member='%s' --role='roles/%s' --format=json",
		gcpServiceAccountEmail,
		iamPolicyBindingMember,
		HumanitecServiceAccountPolicyBindingRole)
	if _, err = iamService.Projects.ServiceAccounts.SetIamPolicy(
		gcpServiceAccountFullID,
		&iam.SetIamPolicyRequest{
			Policy: policy,
		}).Context(ctx).Do(); err != nil {
		return "", fmt.Errorf("failed to set IAM policy for Service Account '%s': %w", gcpServiceAccountEmail, err)
	}
	message.Info("Policy Binding between the service account '%s' and workload identity federation '%s' created", session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName)

	resp, err := p.humanitecPlatform.Client.ListResourceAccountsWithResponse(ctx, orgID)
	if err != nil {
		return "", fmt.Errorf("failed to get Cloud Accounts registered under Humanitec: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("failed to get Cloud Accounts registered under Humanitec: unexpected status code %d instead of %d", resp.StatusCode(), http.StatusOK)
	}
	var cloudAccountExists bool
	for _, cloudAccount := range *resp.JSON200 {
		if cloudAccount.Id == cloudAccountId {
			cloudAccountExists = true
			message.Info("Cloud Account '%s' already exists in Humanitec", cloudAccountId)
		}
	}
	if !cloudAccountExists {
		message.Info("Creating Humanitec Cloud Account. This can take a while as a test connection with GCP Workload Federation is performed too.")
		if err := createResourceAccountWithRetries(ctx, p.humanitecPlatform.Client, orgID,
			client.CreateResourceAccountRequestRequest{
				Id:   cloudAccountId,
				Name: cloudAccountName,
				Type: HumanitecCloudAccountGCPIdentityType,
				Credentials: map[string]interface{}{
					"gcp_service_account": gcpServiceAccountEmail,
					"gcp_audience": fmt.Sprintf("//iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/providers/%s",
						projectNumber, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName),
				},
			}, 2*time.Minute); err != nil {
			return "", err
		}
	}

	return cloudAccountId, nil
}

func (p *gcpProvider) ListClusters(ctx context.Context) ([]string, error) {
	containerService, err := container.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create a container service for gcp: %w", err)
	}

	list, err := containerService.Projects.Zones.Clusters.List(session.State.GCPProvider.GPCProject.ProjectID, "-").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	var output = make([]string, 0, len(list.Clusters))
	var clusters = map[string]session.ClustersInfo{}
	for _, cluster := range list.Clusters {
		clusters[cluster.Name] = session.ClustersInfo{
			ID:       cluster.Id,
			Location: cluster.Location,
			// When private config is not nil, then private endpoint is available
			PrivateEnabled: cluster.PrivateClusterConfig != nil,
			// When enable-private-endpoint is true, the public endpoint is disabled.
			PrivateOnly: cluster.PrivateClusterConfig != nil && cluster.PrivateClusterConfig.EnablePrivateEndpoint,
		}
		output = append(output, cluster.Name)
	}

	session.State.GCPProvider.GKEClusters.ClustersMap = clusters
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return output, nil
}

func (p *gcpProvider) ListLoadBalancers(ctx context.Context, clusterName string) ([]string, error) {
	if err := p.ensureK8sClient(ctx); err != nil {
		return nil, fmt.Errorf("failed to generate a kubeconfig and a client to access the cluster '%s': %w", clusterName, err)
	}

	list, err := p.k8sClient.CoreV1().Services("").List(ctx, k8s_meta.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services in cluster '%s': %w", clusterName, err)
	}

	outputs := make([]string, 0)
	var loadBalancers = map[string]session.LoadBalancerInfo{}
	for _, service := range list.Items {
		if service.Spec.Type == "LoadBalancer" {
			if len(service.Status.LoadBalancer.Ingress) > 0 {
				if service.Status.LoadBalancer.Ingress[0].IP != "" {
					loadBalancers[service.Name+"."+service.Namespace] = session.LoadBalancerInfo{
						Ip: service.Status.LoadBalancer.Ingress[0].IP,
					}
				} else if service.Status.LoadBalancer.Ingress[0].Hostname != "" {
					loadBalancers[service.Name+"."+service.Namespace] = session.LoadBalancerInfo{
						Ip: service.Status.LoadBalancer.Ingress[0].Hostname,
					}
				}
			}
			outputs = append(outputs, service.Name+"."+service.Namespace)
		}
	}

	session.State.GCPProvider.GKEClusters.LoadBalancersMap = loadBalancers
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	return outputs, nil
}

// Actions taken from https://developer.humanitec.com/integration-and-extensions/containerization/kubernetes/#gke.
// Kubernetes Cluster role + IAM cluster acess custom role Option.
func (p *gcpProvider) ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error) {
	projectID := session.State.GCPProvider.GPCProject.ProjectID

	var iamCustomRoleExists bool
	iamService, err := iam.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return "", fmt.Errorf("failed to create iam service: %w", err)
	}

	if savedRole := session.State.GCPProvider.ConnectCluster.IAMCustomRoleName; savedRole != "" {
		role, err := iamService.Roles.Get(fmt.Sprintf("projects/%s/roles/%s", projectID, savedRole)).Context(ctx).Do()
		if err != nil {
			if notFound, parsedErr := isGoogleGRPCErrorNotFound(err, fmt.Sprintf("failed to check custom role '%s' existence", savedRole)); !notFound {
				return "", parsedErr
			}
			return "", fmt.Errorf("failed to check custom role '%s' existence: %w", savedRole, err)
		} else {
			message.Info("IAM Custom Role '%s' already exists: %s", savedRole, role.Description)
			iamCustomRoleExists = true
		}
	}

	roleName := IAMCustomRoleBaseName + "_" + session.State.GCPProvider.GCPResourcesPostfix
	if !iamCustomRoleExists {
		message.Info("Creating IAM custom role: gcloud iam roles create %s --project %s --title=\"Humanitec GKE Access\" --description=\"%s\" --permissions='%s'",
			roleName,
			projectID,
			IAMCustomRoleDescription,
			"container.clusters.get",
		)
		if _, err = iamService.Projects.Roles.Create(
			"projects/"+projectID,
			&iam.CreateRoleRequest{
				Role: &iam.Role{
					Title:               "Humanitec GKE Access",
					Description:         IAMCustomRoleDescription,
					IncludedPermissions: []string{"container.clusters.get"},
				},
				RoleId: roleName,
			}).Context(ctx).Do(); err != nil {
			return "", fmt.Errorf("failed to create role '%s': %w", roleName, err)
		}

		message.Info("IAM Custom Role '%s' created", roleName)
		session.State.GCPProvider.ConnectCluster.IAMCustomRoleName = roleName
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	gcpServiceAccountEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName, projectID)

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return "", fmt.Errorf("failed to create a resource manager service: %w", err)
	}
	policy, err := crmService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve policy in project '%s': %w", projectID, err)
	}

	iamBindingMember := fmt.Sprintf("serviceAccount:%s", gcpServiceAccountEmail)
	var customIAMRoleBindingFound bool
	for _, binding := range policy.Bindings {
		if binding.Role == fmt.Sprintf("projects/%s/roles/%s", projectID, roleName) {
			if !slices.Contains(binding.Members, iamBindingMember) {
				binding.Members = append(binding.Members, iamBindingMember)
			}
			customIAMRoleBindingFound = true
		}
	}
	if !customIAMRoleBindingFound {
		policy.Bindings = append(policy.Bindings,
			&cloudresourcemanager.Binding{
				Role:    fmt.Sprintf("projects/%s/roles/%s", projectID, roleName),
				Members: []string{iamBindingMember},
			})
	}

	message.Info("Grant the IAM custom role to the GCP Service Account used by the Humanitec Cloud Account: gcloud projects add-iam-policy-binding %s --member='%s' --role='roles/%s'",
		projectID,
		iamBindingMember,
		roleName)
	if _, err = crmService.Projects.SetIamPolicy(
		projectID,
		&cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}).Context(ctx).Do(); err != nil {
		return "", fmt.Errorf("failed to set IAM policy for Service Account '%s': %w", gcpServiceAccountEmail, err)
	}
	message.Info("Policy Binding between the service account '%s' and IAM Custom Role '%s' created", session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName, roleName)

	if err := p.ensureK8sClient(ctx); err != nil {
		return "", fmt.Errorf("failed to generate a kubeconfig and a client to access the cluster '%s': %w", session.State.Application.Connect.CloudClusterId, err)
	}

	var clusterRoleName string
	if savedClusterRole := session.State.GCPProvider.ConnectCluster.K8sClusterRoleName; savedClusterRole != "" {
		clusterRoleName = savedClusterRole
	} else {
		clusterRoleName = K8sClusterRoleBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
	}

	if alreadyExists, err := ensurek8sClusterRole(ctx, p.k8sClient, clusterRoleName); err != nil {
		return "", fmt.Errorf("failed to ensure Cluster Role '%s' exists: %w", clusterRoleName, err)
	} else if alreadyExists {
		message.Info("Kubernetes Cluster Role '%s' already exists", clusterRoleName)
	} else {
		message.Info("Kubernetes Cluster Role '%s' created", clusterRoleName)
		session.State.GCPProvider.ConnectCluster.K8sClusterRoleName = clusterRoleName
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	var clusterRoleBindingExists bool
	if clusterRoleBindingName := session.State.GCPProvider.ConnectCluster.K8sClusterRoleBindingName; clusterRoleBindingName != "" {
		if _, err := p.k8sClient.RbacV1().ClusterRoleBindings().Get(ctx, clusterRoleBindingName, k8s_meta.GetOptions{}); err != nil {
			if !k8s_apierrors.IsNotFound(err) {
				return "", fmt.Errorf("failed to check Cluster Role '%s' existence: %w", clusterRoleBindingName, err)
			}
		} else {
			message.Info("Kubernetes Cluster Role Binding '%s' already exists", clusterRoleBindingName)
			clusterRoleBindingExists = true
		}
	}

	if !clusterRoleBindingExists {
		clusterRoleBindingName := K8sClusterRoleBindingBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		clusterRoleBinding := &k8s_rbac.ClusterRoleBinding{
			ObjectMeta: k8s_meta.ObjectMeta{
				Name: clusterRoleBindingName,
			},
			Subjects: []k8s_rbac.Subject{
				{
					Kind: "User",
					Name: gcpServiceAccountEmail,
				},
			},
			RoleRef: k8s_rbac.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     session.State.GCPProvider.ConnectCluster.K8sClusterRoleName,
			},
		}
		if _, err := p.k8sClient.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, k8s_meta.CreateOptions{}); err != nil {
			return "", fmt.Errorf("failed to create Kubernetes Custom Role Binding '%s': %w", clusterRoleBindingName, err)
		}
		message.Info("Kubernetes Cluster Role Binding '%s' created", clusterRoleBindingName)
		session.State.GCPProvider.ConnectCluster.K8sClusterRoleBindingName = clusterRoleBindingName
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	resp, err := p.humanitecPlatform.Client.GetResourceDefinitionWithResponse(ctx, p.humanitecPlatform.OrganizationId, humanitecClusterId, &client.GetResourceDefinitionParams{})
	if err != nil {
		return "", fmt.Errorf("failed to check existence of Resource Definition '%s': %w", humanitecClusterId, err)
	}
	if resp.StatusCode() == http.StatusOK {
		message.Info("Cluster Resource Definition '%s' exists", clusterId)
	} else if resp.StatusCode() == http.StatusNotFound {
		clusterInfo := session.State.GCPProvider.GKEClusters.ClustersMap[clusterId]

		var lbIp string
		if utils.IsIpLbAddress(loadBalancerName) {
			lbIp = loadBalancerName
		} else {
			lbIp = session.State.GCPProvider.GKEClusters.LoadBalancersMap[loadBalancerName].Ip
		}

		definitionValues := map[string]interface{}{
			"project_id":   session.State.GCPProvider.GPCProject.ProjectID,
			"name":         clusterId,
			"loadbalancer": lbIp,
			"zone":         clusterInfo.Location,
		}

		if clusterInfo.PrivateOnly {
			definitionValues["internal_ip"] = true
		} else if clusterInfo.PrivateEnabled {
			if b, err := message.BoolSelect("Cluster has the private endpoint enabled, do you wish to use it?"); err != nil {
				return "", fmt.Errorf("failed to prompt user: %w", err)
			} else if b {
				definitionValues["internal_ip"] = true
				// Override and set the cluster to private for the rest of the session
				clusterInfo.PrivateOnly = true
				session.State.GCPProvider.GKEClusters.ClustersMap[clusterId] = clusterInfo
			}
		}

		resp, err := p.humanitecPlatform.Client.CreateResourceDefinitionWithResponse(
			ctx, p.humanitecPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
				Id:            humanitecClusterId,
				Name:          humanitecClusterName,
				Type:          "k8s-cluster",
				DriverAccount: &humanitecCloudAccountId,
				DriverType:    "humanitec/k8s-cluster-gke",
				DriverInputs: &client.ValuesSecretsRefsRequest{
					Values: &definitionValues,
				},
			})
		if err != nil {
			return "", fmt.Errorf("failed to create Cluster Resource Definition '%s': %w", humanitecClusterId, err)
		}
		if resp.StatusCode() != http.StatusOK {
			return "", fmt.Errorf("failed to create Cluster Resource Definition '%s': unexpected status code %d instead of %d", humanitecClusterId, resp.StatusCode(), http.StatusOK)
		}
		message.Info("Created Cluster Resource Definition '%s'", humanitecClusterId)
	}

	return humanitecClusterId, nil
}

func (p *gcpProvider) IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error) {
	if session.State.GCPProvider.GKEClusters.ClustersMap[clusterId].PrivateOnly {
		return false, nil
	}
	return true, nil
}

func (p *gcpProvider) WriteKubeConfig(ctx context.Context, clusterId string) (string, error) {
	if err := p.ensureK8sClient(ctx); err != nil {
		return "", fmt.Errorf("failed to generate a kubeconfig and a client to access the cluster '%s': %w", clusterId, err)
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	pathToKubeConfig := path.Join(dirname, ".humctl-wizard", "kubeconfig")

	kubeconfig, err := p.getKubeconfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to produce kubeconfig to connect to the cluster '%s': %w", clusterId, err)
	}

	config, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("failed to produce a clientcmdapi.Config from kubeconfig: %w", err)
	}

	if err := clientcmd.WriteToFile(*config, pathToKubeConfig); err != nil {
		return "", fmt.Errorf("failed to save kubeconfig on file '%s': %w", pathToKubeConfig, err)
	}

	return pathToKubeConfig, nil
}

func (p *gcpProvider) ListSecretManagers(ctx context.Context) ([]string, error) {
	return []string{"gcp-secret-manager"}, nil
}

// Actions taken from:
// - https://developer.humanitec.com/integration-and-extensions/humanitec-operator/how-tos/connect-to-google-cloud-secret-manager/#enable-workload-identity-for-the-humanitec-operator to enable operator to access SM
// - https://developer.humanitec.com/integration-and-extensions/humanitec-operator/how-tos/connect-to-google-cloud-secret-manager/#register-the-secret-store-with-the-operator to create Secret Store CR
func (p *gcpProvider) ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error {
	if err := p.ensureClusterInfo(ctx); err != nil {
		return fmt.Errorf("failed to retrieve cluster info: %w", err)
	}
	if p.clusterInfo.WorkloadIdentityConfig == nil || p.clusterInfo.WorkloadIdentityConfig.WorkloadPool == "" {
		return fmt.Errorf("it is needed to enable workload identity on cluster '%s' before proceeding with operator installation", clusterId)
	}

	svcUsage, err := serviceusage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create a service usage client: %w", err)
	}
	defer svcUsage.Close()

	projectID := session.State.GCPProvider.GPCProject.ProjectID
	projectNumber := session.State.GCPProvider.GPCProject.ProjectNumber

	smService, err := svcUsage.GetService(ctx, &serviceusagepb.GetServiceRequest{
		Name: fmt.Sprintf("projects/%s/services/%s", projectID, "secretmanager.googleapis.com"),
	})
	if err != nil {
		return fmt.Errorf("failed to check if Secret Manager API is enabled in project '%s': %w", projectID, err)
	}

	if smService.State != serviceusagepb.State_ENABLED {
		return fmt.Errorf("please enable Secret Manager API in project '%s' before proceeding", projectID)
	}

	iamService, err := iam.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return fmt.Errorf("failed to create iam service: %w", err)
	}

	var iamCustomRoleExists bool
	if savedRole := session.State.GCPProvider.ConfigureOperatorAccess.IAMRoleSecretManager; savedRole != "" {
		role, err := iamService.Roles.Get(fmt.Sprintf("projects/%s/roles/%s", projectID, savedRole)).Context(ctx).Do()
		if err != nil {
			if notFound, parsedErr := isGoogleGRPCErrorNotFound(err, fmt.Sprintf("failed to check custom role '%s' existence", savedRole)); !notFound {
				return parsedErr
			}
			return fmt.Errorf("failed to check custom role '%s' existence: %w", savedRole, err)
		} else {
			message.Info("IAM Role '%s' exists: %s", savedRole, role.Description)
			iamCustomRoleExists = true
		}
	}

	roleName := IAMSecretManagerRoleBaseName + "_" + session.State.GCPProvider.GCPResourcesPostfix
	if !iamCustomRoleExists {
		message.Info("Creating IAM custom role: gcloud iam roles create %s --title=\"Secret Reader / Write\" -project \"%s\" --description=\"%s\" --permissions='%s'",
			projectID,
			roleName,
			IAMSecretManagerRoleDescription,
			"secretmanager.secrets.create,secretmanager.secrets.delete,secretmanager.secrets.update,secretmanager.versions.add,secretmanager.versions.access,secretmanager.versions.list",
		)
		if _, err = iamService.Projects.Roles.Create(
			"projects/"+projectID,
			&iam.CreateRoleRequest{
				Role: &iam.Role{
					Title:       "Secret Reader / Write",
					Description: IAMSecretManagerRoleDescription,
					IncludedPermissions: []string{
						"secretmanager.secrets.create", "secretmanager.secrets.delete", "secretmanager.secrets.update",
						"secretmanager.versions.add", "secretmanager.versions.access", "secretmanager.versions.list"},
				},
				RoleId: roleName,
			}).Context(ctx).Do(); err != nil {
			return fmt.Errorf("failed to create role '%s': %w", roleName, err)
		}

		message.Info("IAM Role '%s' created", roleName)
		session.State.GCPProvider.ConfigureOperatorAccess.IAMRoleSecretManager = roleName
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return fmt.Errorf("failed to create a resource manager service: %w", err)
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to retrieve policy in project '%s'", projectID)
	}

	iamPolicyBindingMember := fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/humanitec-operator-controller-manager",
		projectNumber, projectID, operatorNamespace)
	var customIAMRoleBindingFound bool
	for _, binding := range policy.Bindings {
		if binding.Role == fmt.Sprintf("projects/%s/roles/%s", projectID, roleName) {
			if !slices.Contains(binding.Members, iamPolicyBindingMember) {
				binding.Members = append(binding.Members, iamPolicyBindingMember)
			}
			customIAMRoleBindingFound = true
		}
	}
	if !customIAMRoleBindingFound {
		policy.Bindings = append(
			policy.Bindings,
			&cloudresourcemanager.Binding{
				Role:    fmt.Sprintf("projects/%s/roles/%s", projectID, roleName),
				Members: []string{iamPolicyBindingMember},
			})
	}
	message.Info("Assigning to the Operator Service Account the role to access the Secret Store: gcloud projects add-iam-policy-binding \"%s\" --member='%s' --role='projects/%s/roles/%s' --format=json",
		projectID,
		iamPolicyBindingMember,
		projectID,
		roleName)
	if _, err = crmService.Projects.SetIamPolicy(
		projectID,
		&cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}).Context(ctx).Do(); err != nil {
		return fmt.Errorf("failed to set IAM policy for Principal '%s': %w", iamPolicyBindingMember, err)
	}
	message.Info("Policy Binding between Principal '%s' and IAM Custom Role '%s' created", iamPolicyBindingMember, roleName)

	if err := cluster.RestartOperatorDeployment(ctx, kubeconfig, operatorNamespace); err != nil {
		return fmt.Errorf("failed to restart operator deployment, %w", err)
	}

	if err := cluster.ApplySecretStore(ctx, kubeconfig, operatorNamespace, humanitecSecretStoreId, &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "humanitec.io/v1alpha1",
			"kind":       "SecretStore",
			"metadata": map[string]interface{}{
				"name":      humanitecSecretStoreId,
				"namespace": operatorNamespace,
				"labels": map[string]interface{}{
					"app.humanitec.io/default-store": "true",
				},
			},
			"spec": map[string]interface{}{
				"gcpsm": map[string]interface{}{
					"projectID": fmt.Sprintf("%d", projectNumber),
					"auth":      map[string]interface{}{},
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to register secret store, %w", err)
	} else {
		message.Info("Secret Store CR for secret store '%s' created", humanitecSecretStoreId)
	}

	alreadyExists, err := ensureSecretStore(ctx, p.humanitecPlatform.Client, p.humanitecPlatform.OrganizationId, humanitecSecretStoreId, client.PostOrgsOrgIdSecretstoresJSONRequestBody{
		Id:      humanitecSecretStoreId,
		Primary: true,
		Gcpsm: &client.GCPSMRequest{
			ProjectId: &projectID,
		},
	},
	)
	if err != nil {
		return fmt.Errorf("failed to ensure Secret Store '%s' is registered in Humanitec: %w", humanitecSecretStoreId, err)
	}
	if alreadyExists {
		message.Info("Secret Store '%s' already registered with Humanitec", humanitecSecretStoreId)
	} else {
		message.Info("Secret Store '%s' registered with Humanitec", humanitecSecretStoreId)
	}
	session.State.GCPProvider.ConfigureOperatorAccess.SecretStoreId = humanitecSecretStoreId
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	return nil
}

func (p *gcpProvider) CleanState(ctx context.Context) error {
	projectID := session.State.GCPProvider.GPCProject.ProjectID

	iamService, err := iam.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return fmt.Errorf("failed to create an IAM service to delete gcp IAM resources: %w", err)
	}

	if wliPoolName := session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName; wliPoolName != "" {
		message.Info("Workload Identity Pool %s will be deleted: gcloud iam workload-identity-pools delete %s --location=\"global\" --project %s", wliPoolName, wliPoolName, projectID)
		b, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to prompt user: %w", err)
		}

		if b {
			fullWlName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, wliPoolName)
			if _, err := iamService.Projects.Locations.WorkloadIdentityPools.Delete(fullWlName).Context(ctx).Do(); err != nil {
				if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to check Workload Identity Pool '%s' existence", wliPoolName)); notFound {
					message.Info("Workload Identity Pool '%s' already deleted", wliPoolName)
				} else {
					return parsedErr
				}
			} else {
				message.Info("Workload Identity Pool '%s' deleted", wliPoolName)
			}

			session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName = ""
			session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if humGCPServiceAccount := session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName; humGCPServiceAccount != "" {
		gcpServiceAccountEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName, projectID)
		message.Info("GCP Service Account %s will be deleted: gcloud iam service-accounts delete %s", gcpServiceAccountEmail, gcpServiceAccountEmail)
		b, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to prompt user: %w", err)
		}

		if b {
			if _, err := iamService.Projects.ServiceAccounts.Delete(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, gcpServiceAccountEmail)).Context(ctx).Do(); err != nil {
				if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to delete GCP Service Account '%s'", gcpServiceAccountEmail)); notFound {
					message.Info("GCP Service Account '%s' already deleted", gcpServiceAccountEmail)
				} else {
					return parsedErr
				}
			} else {
				message.Info("GCP Service Account '%s' deleted", gcpServiceAccountEmail)
			}

			session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountName = ""
			session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountUniqueID = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if gkeAccessIAMCustomRole := session.State.GCPProvider.ConnectCluster.IAMCustomRoleName; gkeAccessIAMCustomRole != "" {
		message.Info("IAM Custom Role %s will be deleted: gcloud iam role delete %s --project %s", gkeAccessIAMCustomRole, gkeAccessIAMCustomRole, projectID)
		b, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to prompt user: %w", err)
		}

		if b {
			gkeAccessIAMCustomRoleFullName := fmt.Sprintf("projects/%s/roles/%s", projectID, gkeAccessIAMCustomRole)
			if _, err := iamService.Projects.Roles.Delete(gkeAccessIAMCustomRoleFullName).Context(ctx).Do(); err != nil {
				if notFound, parsedErr := isGoogleGRPCErrorNotFound(err, fmt.Sprintf("failed to delete IAM Custom Role '%s'", gkeAccessIAMCustomRole)); notFound {
					message.Info("IAM Custom Role '%s' already deleted", gkeAccessIAMCustomRole)
				} else {
					return parsedErr
				}
			} else {
				message.Info("IAM Custom Role '%s' deleted", gkeAccessIAMCustomRole)
			}

			session.State.GCPProvider.ConnectCluster.IAMCustomRoleName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if secretManagerAccessIAMCustomRole := session.State.GCPProvider.ConfigureOperatorAccess.IAMRoleSecretManager; secretManagerAccessIAMCustomRole != "" {
		message.Info("IAM Custom Role %s will be deleted: gcloud iam role delete %s --project %s", secretManagerAccessIAMCustomRole, secretManagerAccessIAMCustomRole, projectID)
		b, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to prompt user: %w", err)
		}

		if b {
			secretManagerAccessIAMCustomRoleFullName := fmt.Sprintf("projects/%s/roles/%s", projectID, secretManagerAccessIAMCustomRole)
			message.Info("Deleting IAM Custom Role: gcloud iam role delete %s --project %s",
				secretManagerAccessIAMCustomRole, projectID)
			if _, err := iamService.Projects.Roles.Delete(secretManagerAccessIAMCustomRoleFullName).Context(ctx).Do(); err != nil {
				if notFound, parsedErr := isGoogleGRPCErrorNotFound(err, fmt.Sprintf("failed to delete IAM Custom Role '%s'", secretManagerAccessIAMCustomRole)); notFound {
					message.Info("IAM Custom Role '%s' already deleted", secretManagerAccessIAMCustomRole)
				} else {
					return parsedErr
				}
			} else {
				message.Info("IAM Custom Role '%s' deleted", secretManagerAccessIAMCustomRole)
			}
			session.State.GCPProvider.ConfigureOperatorAccess.IAMRoleSecretManager = ""
			session.State.GCPProvider.ConfigureOperatorAccess.SecretStoreId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	message.Info("There are no more GCP resources stored in the wizard state file to delete in the project '%s'", projectID)

	b, err := message.BoolSelect("Project ID in the wizard state file will be reset. Proceed?")
	if err != nil {
		return fmt.Errorf("failed to prompt user: %w", err)
	}
	if b {
		session.State.GCPProvider.GPCProject = struct {
			ProjectID     string `json:"projectID"`
			ProjectNumber int64  `json:"projectNumber"`
		}{}
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}

	session.State.GCPProvider.GCPResourcesPostfix = ""
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}
func isGoogleAPIErrorNotFound(err error, msg string) (bool, error) {
	gErr, ok := err.(*googleapi.Error)
	if ok {
		switch gErr.Code {
		case http.StatusNotFound:
			return true, nil
		case http.StatusForbidden:
			return false, fmt.Errorf("%s: permission denied", msg)
		}
	}
	return false, fmt.Errorf("%s: %w", msg, err)
}

func isGoogleGRPCErrorNotFound(err error, msg string) (bool, error) {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.NotFound:
			return true, nil
		case codes.PermissionDenied:
			return false, fmt.Errorf("%s: permission denied", msg)
		default:
			if strings.Contains(st.Message(), "already deleted") {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("%s: %w", msg, err)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func (p *gcpProvider) ensureClusterInfo(ctx context.Context) error {
	projectID := session.State.GCPProvider.GPCProject.ProjectID
	clusterName := session.State.Application.Connect.CloudClusterId

	containerService, err := container.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return fmt.Errorf("failed to create a container service for gcp: %w", err)
	}

	var clusterLocation string
	for name, clusterInfo := range session.State.GCPProvider.GKEClusters.ClustersMap {
		if clusterName == name {
			clusterLocation = clusterInfo.Location
		}
	}

	cluster, err := containerService.Projects.Locations.Clusters.Get(fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, clusterLocation, clusterName)).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch cluster '%s' info: %w", clusterName, err)
	}
	p.clusterInfo = cluster
	return nil
}

func (p *gcpProvider) getKubeconfig(ctx context.Context) ([]byte, error) {
	if err := p.ensureClusterInfo(ctx); err != nil {
		clusterName := session.State.Application.Connect.CloudClusterId
		return nil, fmt.Errorf("failed to fetch cluster '%s' info: %w", clusterName, err)
	}

	cert, err := base64.StdEncoding.DecodeString(
		p.clusterInfo.MasterAuth.ClusterCaCertificate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cluster ca certificate: %w", err)
	}

	token, err := p.credentials.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user token: %w", err)
	}

	return clientcmd.Write(clientcmdapi.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {
				CertificateAuthorityData: cert,
				Server:                   fmt.Sprintf("https://%v", p.clusterInfo.Endpoint),
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"authinfo": {
				Token: token.AccessToken,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"context": {
				Cluster:  "cluster",
				AuthInfo: "authinfo",
			},
		},
		CurrentContext: "context",
	})
}

func (p *gcpProvider) ensureK8sClient(ctx context.Context) error {
	if p.k8sClient != nil {
		return nil
	}

	kubeConfig, err := p.getKubeconfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	p.k8sClient = client
	return nil
}
