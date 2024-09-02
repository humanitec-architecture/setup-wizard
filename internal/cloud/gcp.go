package cloud

import (
	"context"
	"encoding/base64"

	"errors"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	container "google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iam_v1 "google.golang.org/api/iam/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

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
	RoleBaseName                                          = "HumanitecAccessTempcreds"
	RoleDescription                                       = "GKE access least privilege to deploy via Humanitec"
)

type gcpProvider struct {
	id string

	credentials       *google.Credentials
	humanitecPlatform *platform.HumanitecPlatform
}

// NewGCPProvider retrieves the Google Application Default Credentials.
// See: https://cloud.google.com/docs/authentication/application-default-credentials#personal
// User should select which project use.
// The user running the script need this set of permissions:
// - roles/iam.workloadIdentityPoolAdmin
// - roles/iam.serviceAccountAdmin
// - roles/container.developer
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

	projectID, err := message.Select("Select a GCP project", projectsSelection)
	if err != nil {
		return nil, fmt.Errorf("failed to select a GCP project: %w", err)
	}

	session.State.GCPProvider.GPCProject.ProjectID = projectID
	session.State.GCPProvider.GPCProject.ProjectNumber = projectsInfo[projectID].ProjectNumber

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
	oauth2Service, err := oauth2.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return "", fmt.Errorf("failed to create oauth2 service: %w", err)
	}

	tokenInfo, err := oauth2Service.Tokeninfo().Do()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve token info: %w", err)
	}

	return tokenInfo.UserId, nil
}

// Actions taken from: https://developer.humanitec.com/platform-orchestrator/security/cloud-accounts/gcp/#gcp-service-account-impersonation
func (p *gcpProvider) CreateCloudIdentity(ctx context.Context, cloudAccountId, cloudAccountName string) (string, error) {
	projectID := session.State.GCPProvider.GPCProject.ProjectID
	projectNumber := session.State.GCPProvider.GPCProject.ProjectNumber

	iamService, err := iam_v1.NewService(ctx, option.WithCredentials(p.credentials))
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
			message.Info("Workload Identity Pool '%s' exists: %s", storedWliPoolName, wliPool.Description)
		}
	}

	if !wliPoolExists {
		wliPoolName := WorkloadIdentityPoolBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		if _, err := iamService.Projects.Locations.WorkloadIdentityPools.Create(
			fmt.Sprintf("projects/%s/locations/global", projectID),
			&iam_v1.WorkloadIdentityPool{
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

	var wliProviderExists bool
	if storedWliProviderName := session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName; storedWliProviderName != "" {
		fullWlpName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectID, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, storedWliProviderName)
		wliProvider, err := iamService.Projects.Locations.WorkloadIdentityPools.Providers.Get(fullWlpName).Context(ctx).Do()

		if err != nil {
			if notFound, parsedErr := isGoogleAPIErrorNotFound(err, fmt.Sprintf("failed to check Workload Identity Pool Provider '%s' existence", storedWliProviderName)); !notFound {
				return "", parsedErr
			}
		} else if wliProvider != nil && wliProvider.State == "DELETED" {
			return "", fmt.Errorf("workload Identity Pool Provider '%s' has been recently deleted, please restore it", storedWliProviderName)
		} else {
			wliProviderExists = true
			message.Info("Workload Identity Pool Provider '%s' exists: %s", storedWliProviderName, wliProvider.Description)
		}
	}

	if !wliProviderExists {
		wliProviderName := OIDCWorkloadIdentityPoolProviderBaseName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		if _, err := iamService.Projects.Locations.WorkloadIdentityPools.Providers.Create(
			fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName),
			&iam_v1.WorkloadIdentityPoolProvider{
				Description: OIDCWorkloadIdentityPoolProviderDescription,
				Oidc: &iam_v1.Oidc{
					IssuerUri: OIDCWorkloadIdentityPoolProviderIssuerURI,
				},
				AttributeMapping: map[string]string{OIDCWorkloadIdentityPoolProviderAttributeMappingKey: OIDCWorkloadIdentityPoolProviderAttributeMappingValue},
			},
		).WorkloadIdentityPoolProviderId(wliProviderName).Context(ctx).Do(); err != nil {
			return "", fmt.Errorf("failed to create Workload Identity Pool Provider '%s': %w", wliProviderName, err)
		}
		session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName = wliProviderName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Workload Identity Pool Provider '%s' created.", wliProviderName)
	}

	var humServiceAccountExists bool
	if humStoredServiceAccount := session.State.GCPProvider.CloudIdentity.HumanitecServiceAccountUniqueID; humStoredServiceAccount != "" {
		humSA, err := iamService.Projects.ServiceAccounts.Get(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, humStoredServiceAccount)).Context(ctx).Do()
		if err != nil {
			if notFound, parsedErr := isGoogleGRPCErrorNotFound(err, fmt.Sprintf("failed to check Role '%s' existence", RoleBaseName)); !notFound {
				return "", parsedErr
			}
		} else {
			humServiceAccountExists = true
			message.Info("Service Account with unique ID '%s' exists: %s", humStoredServiceAccount, humSA.Description)
		}
	}
	if !humServiceAccountExists {
		saName := HumanitecServiceAccountName + "-" + session.State.GCPProvider.GCPResourcesPostfix
		var sa *iam_v1.ServiceAccount
		if sa, err = iamService.Projects.ServiceAccounts.Create(
			fmt.Sprintf("projects/%s", projectID),
			&iam_v1.CreateServiceAccountRequest{
				AccountId: saName,
				ServiceAccount: &iam_v1.ServiceAccount{
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
	var workloadIdentityUserBindingFound bool
	for _, binding := range policy.Bindings {
		if binding.Role == "roles/"+HumanitecServiceAccountPolicyBindingRole {
			binding.Members = append(binding.Members, fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/subject/%s/%s",
				projectNumber, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, orgID, cloudAccountId))
			workloadIdentityUserBindingFound = true
		}
	}
	if !workloadIdentityUserBindingFound {
		policy.Bindings = append(policy.Bindings, &iam_v1.Binding{
			Role: "roles/" + HumanitecServiceAccountPolicyBindingRole,
			Members: []string{fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/subject/%s/%s",
				projectNumber, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, orgID, cloudAccountId)},
		})
	}

	_, err = iamService.Projects.ServiceAccounts.SetIamPolicy(gcpServiceAccountFullID, &iam_v1.SetIamPolicyRequest{
		Policy: policy,
	}).Context(ctx).Do()
	if err != nil {
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
			message.Info("Cloud Account '%s' exists in Humanitec", cloudAccountId)
		}
	}
	if cloudAccountExists {
		if err := CheckResourceAccount(ctx, p.humanitecPlatform.Client, orgID, cloudAccountId); err != nil {
			return "", err
		}
	} else {
		if err := CreateResourceAccount(ctx, p.humanitecPlatform.Client, orgID,
			client.CreateResourceAccountRequestRequest{
				Id:   cloudAccountId,
				Name: cloudAccountName,
				Type: HumanitecCloudAccountGCPIdentityType,
				Credentials: map[string]interface{}{
					"gcp_service_account": gcpServiceAccountEmail,
					"gcp_audience": fmt.Sprintf("//iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/providers/%s",
						projectNumber, session.State.GCPProvider.CloudIdentity.WorkloadIdentityPoolName, session.State.GCPProvider.CloudIdentity.OidcWorkloadIdentityPoolProviderName),
				},
			}); err != nil {
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
	projectID := session.State.GCPProvider.GPCProject.ProjectID

	containerService, err := container.NewService(ctx, option.WithCredentials(p.credentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create a container service for gcp: %w", err)
	}

	var clusterLocation string
	for name, clusterInfo := range session.State.GCPProvider.GKEClusters.ClustersMap {
		if clusterName == name {
			clusterLocation = clusterInfo.Location
		}
	}

	cluster, err := containerService.Projects.Zones.Clusters.Get(projectID, clusterLocation, clusterName).
		Name(fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, clusterLocation, clusterName)).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cluster '%s' info: %w", clusterName, err)
	}
	token, err := p.credentials.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user token: %w", err)
	}
	k8sClient, err := getK8sClient(cluster, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a client to access the cluster '%s': %w", cluster.Id, err)
	}

	list, err := k8sClient.CoreV1().Services("").List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services in cluster '%s': %w", cluster.Id, err)
	}

	outputs := make([]string, 0)
	for _, service := range list.Items {
		if service.Spec.Type == "LoadBalancer" {
			outputs = append(outputs, service.Name)
		}
	}

	return outputs, nil
}

func (p *gcpProvider) ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error) {
	return "", errors.New("not implemented yet")
}

func (p *gcpProvider) IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error) {
	return false, errors.New("not implemented yet")
}

func (p *gcpProvider) WriteKubeConfig(ctx context.Context, clusterId string) (string, error) {
	return "", errors.New("not implemented yet")
}

func (p *gcpProvider) ListSecretManagers() ([]string, error) {
	return []string{}, errors.New("not implemented yet")
}

func (p *gcpProvider) IsOperatorInstalled(ctx context.Context) (bool, error) {
	return false, errors.New("not implemented yet")
}

func (p *gcpProvider) ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error {
	return errors.New("not implemented yet")
}

func isGoogleGRPCErrorNotFound(err error, msg string) (bool, error) {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.NotFound:
			return true, nil
		case codes.PermissionDenied:
			return false, fmt.Errorf("%s: permission denied", msg)
		}
	}
	return false, fmt.Errorf("%s: %w", msg, err)
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

const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func getK8sClient(cluster *container.Cluster, token string) (*kubernetes.Clientset, error) {
	id := cluster.Id

	cert, err := base64.StdEncoding.DecodeString(
		cluster.MasterAuth.ClusterCaCertificate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cluster ca certificate: %w", err)
	}

	kubeConfig, err := clientcmd.Write(clientcmdapi.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: map[string]*clientcmdapi.Cluster{
			id: {
				CertificateAuthorityData: cert,
				Server:                   fmt.Sprintf("https://%v", cluster.Endpoint),
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			id: {
				Token: token,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			id: {
				Cluster:  id,
				AuthInfo: id,
			},
		},
		CurrentContext: id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s API client: %w", err)
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s API client: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s API client: %w", err)
	}
	return client, nil
}
