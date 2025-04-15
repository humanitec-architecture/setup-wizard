package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	k8s_rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	azureIdRegex = regexp.MustCompile(`(?i)/subscriptions/[-_a-zA-Z0-9]+/resourcegroups/([-_a-zA-Z0-9]+)/providers/Microsoft.[a-zA-Z]+/[a-zA-Z]+/([-_a-zA-Z0-9]+)`)
)

func getAzureResourceGroupAndName(id string) (string, string, error) {
	match := azureIdRegex.FindStringSubmatch(id)
	if len(match) < 3 {
		return "", "", fmt.Errorf("can't retrieve name and resource group from Azure ID: %s", id)
	}
	return match[1], match[2], nil
}

type azureProvider struct {
	credential        azcore.TokenCredential
	humanitecPlatform *platform.HumanitecPlatform
	clusters          map[string]*armcontainerservice.ManagedCluster
	k8sClients        map[string]*kubernetes.Clientset
	kubeconfigs       map[string]clientcmdapi.Config
}

func NewAzureProvider(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (Provider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load azure default credentials, %w", err)
	}

	return &azureProvider{
		credential:        cred,
		humanitecPlatform: humanitecPlatform,
		clusters:          map[string]*armcontainerservice.ManagedCluster{},
		k8sClients:        map[string]*kubernetes.Clientset{},
		kubeconfigs:       map[string]clientcmdapi.Config{},
	}, nil
}

func (p *azureProvider) GetCallingUserId(ctx context.Context) (string, error) {
	token, err := p.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com//.default"}})
	if err != nil {
		return "", fmt.Errorf("failed to get access token, %w", err)
	}
	claims := make(jwt.MapClaims)
	if _, _, err = jwt.NewParser().ParseUnverified(token.Token, claims); err != nil {
		return "", fmt.Errorf("failed to parse access token, %w", err)
	}
	name, _ := claims["unique_name"].(string)
	return name, nil
}

func (p *azureProvider) SetupProvider(ctx context.Context) error {
	// Select subscription
	if session.State.AzureProvider.SubscriptionID == "" {
		subList, err := p.getSubscriptionList(ctx)
		if err != nil {
			return fmt.Errorf("failed to get Subscription list, %w", err)
		}
		if len(subList) > 0 {
			subID, err := message.Select("Select Azure Subscription:", subList)
			if err != nil {
				return fmt.Errorf("failed to select Subscription: %w", err)
			}
			session.State.AzureProvider.SubscriptionID = subID
		} else {
			return errors.New("no Subscriptions available for the current account")
		}
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	} else {
		message.Info("Using Subscription from previous session: %s", session.State.AzureProvider.SubscriptionID)
	}

	// Select Resource group
	rgClient, err := armresources.NewResourceGroupsClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create Resource Group client, %w", err)
	}
	if session.State.AzureProvider.ResourceGroup != "" {
		_, err = rgClient.Get(ctx, session.State.AzureProvider.ResourceGroup, nil)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				message.Debug("Azure Resource Group not found: %s, clearing state", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName)
				session.State.AzureProvider.ResourceGroup = ""
			} else {
				return fmt.Errorf("failed to check if Resource Group exists, %w", err)
			}
		} else {
			message.Info("Using Resource Group from previous session: %s", session.State.AzureProvider.ResourceGroup)
		}
	}
	if session.State.AzureProvider.ResourceGroup == "" {
		grList, grRegionMap, err := p.getResourceGroups(ctx, rgClient)
		if err != nil {
			return fmt.Errorf("failed to get Resource Group list, %w", err)
		}
		resourceGroup, err := message.Select("Select Azure Resource Group:", grList)
		if err != nil {
			return fmt.Errorf("failed to select Resource Group: %w", err)
		}
		session.State.AzureProvider.ResourceGroup = resourceGroup
		session.State.AzureProvider.Region = grRegionMap[resourceGroup]
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}

	return nil
}

func (p *azureProvider) CreateCloudIdentity(ctx context.Context, humanitecCloudAccountId, humanitecCloudAccountName string) (string, error) {
	// Create Managed Identity
	idClient, err := armmsi.NewUserAssignedIdentitiesClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Managed Identity client, %w", err)
	}

	if session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName != "" {
		_, err = idClient.Get(ctx,
			session.State.AzureProvider.ResourceGroup,
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
			nil,
		)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				message.Debug("Azure Managed Identity not found: %s, clearing state", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName)
				session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName = ""
				session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityClientId = ""
				session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityTenantId = ""
				session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId = ""
			} else {
				return "", fmt.Errorf("failed to check if Managed Identity exists, %w", err)
			}
		} else {
			message.Info("Using Managed Identity from previous session: %s", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName)
		}
	}

	if session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName == "" {
		resourceName, err := message.Prompt("Enter a name for new Managed Identity:", "humanitec-account-identity")
		if err != nil {
			return "", fmt.Errorf("failed to select Managed Identity name: %w", err)
		}
		message.Info("Creating Managed Identity: az identity create --name %s --resource-group %s", resourceName, session.State.AzureProvider.ResourceGroup)
		resp, err := idClient.CreateOrUpdate(ctx,
			session.State.AzureProvider.ResourceGroup,
			resourceName,
			armmsi.Identity{
				Location: to.Ptr(session.State.AzureProvider.Region),
			},
			nil)
		if err != nil {
			return "", fmt.Errorf("failed to create Managed Identity, %w", err)
		}
		if err = p.waitManagedIdentityCreated(ctx, session.State.AzureProvider.ResourceGroup, resourceName, idClient); err != nil {
			return "", fmt.Errorf("error waiting for Managed Identity to be created, %w", err)
		}
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName = *resp.Name
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityClientId = *resp.Properties.ClientID
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityTenantId = *resp.Properties.TenantID
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId = *resp.Properties.PrincipalID
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	// Create federated credentials
	fedClient, err := armmsi.NewFederatedIdentityCredentialsClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Federated Credentials client, %w", err)
	}
	if session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName != "" {
		_, err = fedClient.Get(ctx,
			session.State.AzureProvider.ResourceGroup,
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
			session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName,
			nil,
		)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				message.Debug("Azure Federated Credentials not found: %s, clearing state", session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName)
				session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName = ""
			} else {
				return "", fmt.Errorf("failed to check if Federeted Credentials exist, %w", err)
			}
		} else {
			message.Info("Using Federated Credentials from previous session: %s", session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName)
		}
	}

	if session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName == "" {
		resourceName, err := message.Prompt("Enter a name for new Federated Credentials:", "access-from-humanitec")
		if err != nil {
			return "", fmt.Errorf("failed to select Fedareted Credentials name: %w", err)
		}
		message.Info("Creating Federated Identity Credentials: az identity federated-credential create --name %s --identity-name %s --resource-group %s --issuer https://idtoken.humanitec.io --subject %s --audience api://AzureADTokenExchange",
			resourceName,
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
			session.State.AzureProvider.ResourceGroup,
			p.humanitecPlatform.OrganizationId+"/"+humanitecCloudAccountId)

		resp, err := fedClient.CreateOrUpdate(ctx,
			session.State.AzureProvider.ResourceGroup,
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
			resourceName,
			armmsi.FederatedIdentityCredential{
				Properties: &armmsi.FederatedIdentityCredentialProperties{
					Audiences: []*string{to.Ptr("api://AzureADTokenExchange")},
					Issuer:    to.Ptr("https://idtoken.humanitec.io"),
					Subject:   to.Ptr(p.humanitecPlatform.OrganizationId + "/" + humanitecCloudAccountId),
				},
			},
			nil)
		if err != nil {
			return "", fmt.Errorf("failed to create Federated Credentials, %w", err)
		}
		if err = p.waitFederatedCredentialsCreated(ctx,
			session.State.AzureProvider.ResourceGroup,
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
			resourceName,
			fedClient); err != nil {
			return "", fmt.Errorf("error waiting for Federated Credentials to be created, %w", err)
		}
		session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName = *resp.Name
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	// Create Humanitec Cloud Account
	if session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId != "" {
		getCloudAccountResp, err := p.humanitecPlatform.Client.GetResourceAccountWithResponse(ctx, p.humanitecPlatform.OrganizationId, session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId)
		if err != nil {
			return "", fmt.Errorf("failed to get resource account, %w", err)
		}
		if getCloudAccountResp.StatusCode() == 404 {
			message.Debug("Humanitec Cloud Account not found: %s, clearing state", session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId)
			session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId = ""
		} else if getCloudAccountResp.StatusCode() != 200 {
			return "", fmt.Errorf("humanitec returned unexpected status code: %d with body %s", getCloudAccountResp.StatusCode(), string(getCloudAccountResp.Body))
		}
	}

	if session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId == "" {
		message.Info("Creating Humanitec Cloud Account: %s", humanitecCloudAccountId)
		// The new federated credentials could take a few seconds to be propagated, so create Account with retries (as we do credentials check)
		if err := createResourceAccountWithRetries(ctx, p.humanitecPlatform.Client, p.humanitecPlatform.OrganizationId, client.CreateResourceAccountRequestRequest{
			Id:   humanitecCloudAccountId,
			Name: humanitecCloudAccountName,
			Type: "azure-identity",
			Credentials: map[string]interface{}{
				"azure_identity_tenant_id": session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityTenantId,
				"azure_identity_client_id": session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityClientId,
			},
		}, 30*time.Second); err != nil {
			return "", fmt.Errorf("failed to create resource account, %w", err)
		}

		session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId = humanitecCloudAccountId
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	} else {
		message.Info("Humanitec Cloud Account already created, loading from state: %s", session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId)
	}

	return session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId, nil
}

func (p *azureProvider) ListClusters(ctx context.Context) ([]string, error) {
	clientFactory, err := armcontainerservice.NewClientFactory(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client, %w", err)
	}
	list := make([]string, 0)
	pager := clientFactory.NewManagedClustersClient().NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			list = append(list, *v.ID)
			p.clusters[*v.ID] = v
		}
	}
	return list, nil
}

func (p *azureProvider) ListLoadBalancers(ctx context.Context, clusterId string) ([]string, error) {
	cluster, err := p.getCluster(ctx, clusterId)
	if err != nil {
		return nil, err
	}
	clientset, err := p.getK8sClient(ctx, *cluster)
	if err != nil {
		return nil, err
	}
	return listLoadBalancers(ctx, clientset)
}

func (p *azureProvider) ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error) {

	// Create a Role Assignment to the Managed Identity
	clientFactory, err := armauthorization.NewClientFactory(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure authorization client, %w", err)
	}
	azClient := clientFactory.NewRoleAssignmentsClient()

	roleID := "4abbcc35-e782-43d8-92c5-2d3f1bd2253f" // Built-in "Azure Kubernetes Service Cluster User Role" role
	aksClusterUserRoleID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		session.State.AzureProvider.SubscriptionID, roleID)

	message.Info("Assigning AKS CLuster User Role to the managed identity: az role assignment create --assignee %s --role %s --scope %s",
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId,
		aksClusterUserRoleID,
		clusterId)

	err = p.createRoleAssignmentWithRetries(ctx, azClient, clusterId, armauthorization.RoleAssignmentProperties{
		PrincipalID:      to.Ptr(session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId),
		RoleDefinitionID: to.Ptr(aksClusterUserRoleID),
		PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
	}, 30*time.Second)
	if err != nil {
		return "", err
	}

	// Create Entra ID group for the identity and add AKS Cluster User Role
	grClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(p.credential, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return "", fmt.Errorf("failed to create Graph client, %w", err)
	}
	if session.State.AzureProvider.ConnectCluster.EntraIDGroupId != "" {
		groupList, err := grClient.Groups().Get(ctx, &groups.GroupsRequestBuilderGetRequestConfiguration{
			QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
				Filter: to.Ptr("id eq '" + session.State.AzureProvider.ConnectCluster.EntraIDGroupId + "'"),
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to check if Entra ID group exists, %w", err)
		}
		if len(groupList.GetValue()) == 0 {
			message.Debug("Azure Role Assignment not found: %s, clearing state", session.State.AzureProvider.ConnectCluster.EntraIDGroupName)
			session.State.AzureProvider.ConnectCluster.EntraIDGroupName = ""
			session.State.AzureProvider.ConnectCluster.EntraIDGroupId = ""
		} else {
			message.Info("Using Entra ID group from previous session: %s (ID %s)", session.State.AzureProvider.ConnectCluster.EntraIDGroupName, session.State.AzureProvider.ConnectCluster.EntraIDGroupId)
		}
	}

	if session.State.AzureProvider.ConnectCluster.EntraIDGroupId == "" {
		groupName, err := message.Prompt("Enter a name for Entra ID security group to create a cluster binding:", "humanitec-sec-group")
		if err != nil {
			return "", fmt.Errorf("failed to select Entra ID group name: %w", err)
		}

		groupList, err := grClient.Groups().Get(ctx, &groups.GroupsRequestBuilderGetRequestConfiguration{
			QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
				Filter: to.Ptr("displayName eq '" + groupName + "'"),
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to check if Entra ID group exists, %w", err)
		}

		if len(groupList.GetValue()) == 0 {
			message.Info("Creating Entra ID security group: az ad group create --display-name %s --mail-nickname %s",
				groupName, groupName)
			reqBody := models.NewGroup()
			reqBody.SetDisplayName(to.Ptr(groupName))
			reqBody.SetDescription(to.Ptr("Humanitec Identity Security Group"))
			reqBody.SetMailNickname(to.Ptr(groupName))
			reqBody.SetMailEnabled(to.Ptr(false))
			reqBody.SetSecurityEnabled(to.Ptr(true))
			result, err := grClient.Groups().Post(ctx, reqBody, &groups.GroupsRequestBuilderPostRequestConfiguration{})
			if err != nil {
				return "", fmt.Errorf("failed to create Entra ID group, %w", err)
			}
			session.State.AzureProvider.ConnectCluster.EntraIDGroupName = *result.GetDisplayName()
			session.State.AzureProvider.ConnectCluster.EntraIDGroupId = *result.GetId()
		} else {
			message.Info("Entra ID security group already exists: %s", groupName)
			session.State.AzureProvider.ConnectCluster.EntraIDGroupName = groupName
			session.State.AzureProvider.ConnectCluster.EntraIDGroupId = *groupList.GetValue()[0].GetId()
		}
		if err = session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
	}

	// Add managed identity to the group
	reqBody := models.NewReferenceCreate()
	odataId := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryObjects/%s", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId)
	reqBody.SetOdataId(&odataId)
	if err = grClient.Groups().
		ByGroupId(session.State.AzureProvider.ConnectCluster.EntraIDGroupId).
		Members().Ref().Post(ctx, reqBody, nil); err != nil {

		if strings.Contains(err.Error(), "already exist") {
			message.Info("Managed Identity %s already added to Entra ID Group", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId)
		} else {
			return "", fmt.Errorf("failed to add the Managed Identity to Entra ID Group, %w", err)
		}
	} else {
		message.Info("Managed Identity %s added to Entra ID Group", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId)
	}

	// Create AKS CLuster User Role Assignment for the group
	message.Info("Assigning AKS CLuster User Role to the group: az role assignment create --assignee %s --role %s --scope %s",
		session.State.AzureProvider.ConnectCluster.EntraIDGroupId,
		aksClusterUserRoleID,
		clusterId)

	err = p.createRoleAssignmentWithRetries(ctx, azClient, clusterId, armauthorization.RoleAssignmentProperties{
		PrincipalID:      to.Ptr(session.State.AzureProvider.ConnectCluster.EntraIDGroupId),
		RoleDefinitionID: to.Ptr(aksClusterUserRoleID),
		PrincipalType:    to.Ptr(armauthorization.PrincipalTypeGroup),
	}, 30*time.Second)
	if err != nil {
		return "", err
	}

	// Set K8s RBAC
	cluster, err := p.getCluster(ctx, clusterId)
	if err != nil {
		return "", err
	}
	clientset, err := p.getK8sClient(ctx, *cluster)
	if err != nil {
		return "", err
	}
	if session.State.AzureProvider.ConnectCluster.K8s == nil {
		session.State.AzureProvider.ConnectCluster.K8s = &session.K8s{}
	}
	rbacSubject := k8s_rbac.Subject{
		Kind: "Group",
		Name: session.State.AzureProvider.ConnectCluster.EntraIDGroupId,
	}
	if err = createClusterRoleAndBinding(ctx, clientset, rbacSubject, session.State.AzureProvider.ConnectCluster.K8s); err != nil {
		return "", err
	}
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save state: %w", err)
	}

	// Get loadbalancer host or IP
	lb := session.State.Application.Connect.LoadBalancers[loadBalancerName]
	message.Debug("Using load balancer: %s", lb)

	// Create Resource Definition
	message.Info("Creating Cluster Resource Definition '%s'", humanitecClusterId)
	resourceGroup, _, err := getAzureResourceGroupAndName(clusterId)
	if err != nil {
		return "", err
	}
	resp, err := p.humanitecPlatform.Client.GetResourceDefinitionWithResponse(ctx, p.humanitecPlatform.OrganizationId, humanitecClusterId, &client.GetResourceDefinitionParams{})
	if err != nil {
		return "", fmt.Errorf("failed to check existence of Resource Definition '%s': %w", humanitecClusterId, err)
	}
	if resp.StatusCode() == http.StatusOK {
		message.Info("Cluster Resource Definition '%s' exists", clusterId)
	} else if resp.StatusCode() == http.StatusNotFound {
		entraidEnabled, err := p.isMicrosoftEntraIDEnabled(ctx, *cluster)
		if err != nil {
			return "", fmt.Errorf("failed to check if Entra ID is enabled on the cluster %s: %w", *cluster.Name, err)
		}
		values := map[string]interface{}{
			"name":            *cluster.Name,
			"resource_group":  resourceGroup,
			"subscription_id": session.State.AzureProvider.SubscriptionID,
			"loadbalancer":    lb,
		}
		if entraidEnabled {
			values["server_app_id"] = "6dae42f8-4368-4678-94ff-3960e28e3630"
		}

		defResp, err := p.humanitecPlatform.Client.CreateResourceDefinitionWithResponse(
			ctx, p.humanitecPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
				Id:            humanitecClusterId,
				Name:          humanitecClusterName,
				Type:          "k8s-cluster",
				DriverAccount: &humanitecCloudAccountId,
				DriverType:    "humanitec/k8s-cluster-aks",
				DriverInputs: &client.ValuesSecretsRefsRequest{
					Values: &values,
				},
			})
		if err != nil {
			return "", fmt.Errorf("failed to create Cluster Resource Definition '%s': %w", humanitecClusterId, err)
		}
		if defResp.StatusCode() != http.StatusOK {
			return "", fmt.Errorf("failed to create Cluster Resource Definition '%s': unexpected status code %d instead of %d", humanitecClusterId, resp.StatusCode(), http.StatusOK)
		}
	}

	return humanitecClusterId, nil
}

func (p *azureProvider) IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error) {
	cluster, err := p.getCluster(ctx, clusterId)
	if err != nil {
		return false, err
	}
	return cluster.Properties.PrivateFQDN == nil, nil
}

func (p *azureProvider) WriteKubeConfig(ctx context.Context, clusterId string) (string, error) {
	kubeconfig, ok := p.kubeconfigs[clusterId]
	if !ok {
		// ensure kubeconfig is created
		cluster, err := p.getCluster(ctx, clusterId)
		if err != nil {
			return "", err
		}
		if _, err = p.getK8sClient(ctx, *cluster); err != nil {
			return "", err
		}
		kubeconfig = p.kubeconfigs[clusterId]
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	pathToKubeConfig := path.Join(dirname, ".humctl-wizard", "kubeconfig")
	if err := clientcmd.WriteToFile(kubeconfig, pathToKubeConfig); err != nil {
		return "", fmt.Errorf("failed to save kubeconfig on file '%s': %w", pathToKubeConfig, err)
	}
	return pathToKubeConfig, nil
}

func (p *azureProvider) ListSecretManagers(ctx context.Context) ([]string, error) {
	kvClient, err := armkeyvault.NewVaultsClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client, %w", err)
	}
	list := make([]string, 0)
	pager := kvClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			list = append(list, *v.ID)
		}
	}
	return list, nil
}

func (p *azureProvider) ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error {
	kvClient, err := armkeyvault.NewVaultsClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client, %w", err)
	}
	resourceGroup, name, err := getAzureResourceGroupAndName(secretManager)
	if err != nil {
		return err
	}
	keyVault, err := kvClient.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure Key Vault %s, %w", secretManager, err)
	}

	// Register Secret Store in Humanitec
	message.Info("Registering Secret Store with Humanitec: %s", humanitecSecretStoreId)
	alreadyExists, err := ensureSecretStore(ctx, p.humanitecPlatform.Client, p.humanitecPlatform.OrganizationId, humanitecSecretStoreId,
		client.PostOrgsOrgIdSecretstoresJSONRequestBody{
			Id:      humanitecSecretStoreId,
			Primary: true,
			Azurekv: &client.AzureKVRequest{
				Url:      keyVault.Properties.VaultURI,
				TenantId: keyVault.Properties.TenantID,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to ensure Secret Store '%s' is registered in Humanitec: %w", humanitecSecretStoreId, err)
	}
	if alreadyExists {
		message.Info("Secret Store '%s' already registered with Humanitec", humanitecSecretStoreId)
	}
	session.State.GCPProvider.ConfigureOperatorAccess.SecretStoreId = humanitecSecretStoreId
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	// Configure access to Key Vault from cluster (we use resourceGroup from Key Vault here)
	opCluster, err := p.getCluster(ctx, clusterId)
	if err != nil {
		return err
	}
	if err = p.enableIdentityInCluster(ctx, *opCluster, resourceGroup, operatorNamespace, "humanitec-operator-controller-manager"); err != nil {
		return err
	}

	if *keyVault.Properties.EnableRbacAuthorization {
		// Create role assignment to use Key Vault (if RBAC mode enabled on the Key Vault)
		clientFactory, err := armauthorization.NewClientFactory(session.State.AzureProvider.SubscriptionID, p.credential, nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure authorization client, %w", err)
		}
		azClient := clientFactory.NewRoleAssignmentsClient()
		roleID := "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" // Built-in "Key Vault Secrets Officer" role
		aksKVSecretOfficerID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
			session.State.AzureProvider.SubscriptionID, roleID)

		message.Info("Assigning Key Vault Secrets Officer Role to the managed identity: az role assignment create --assignee %s --role %s --scope %s",
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId,
			aksKVSecretOfficerID,
			*keyVault.ID)

		err = p.createRoleAssignmentWithRetries(ctx, azClient, *keyVault.ID, armauthorization.RoleAssignmentProperties{
			PrincipalID:      to.Ptr(session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId),
			RoleDefinitionID: to.Ptr(aksKVSecretOfficerID),
			PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
		}, 30*time.Second)
		if err != nil {
			return err
		}
		message.Debug("KeyVault RBAC authorization configured ")
	} else {
		// Configure access policies (legacy)
		accessPolicy := armkeyvault.AccessPolicyEntry{
			TenantID: keyVault.Properties.TenantID,
			ObjectID: to.Ptr(session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId),
			Permissions: &armkeyvault.Permissions{
				Secrets: []*armkeyvault.SecretPermissions{
					to.Ptr(armkeyvault.SecretPermissionsGet),
					to.Ptr(armkeyvault.SecretPermissionsSet),
					to.Ptr(armkeyvault.SecretPermissionsDelete),
					to.Ptr(armkeyvault.SecretPermissionsRecover),
				},
			},
		}
		message.Info("Updating Key Vault access policy: az keyvault set-policy --name %s --secret-permissions \"get set delete recover\" --spn %s",
			name,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId)
		_, err = kvClient.UpdateAccessPolicy(ctx, resourceGroup, name, armkeyvault.AccessPolicyUpdateKindAdd, armkeyvault.VaultAccessPolicyParameters{
			Properties: &armkeyvault.VaultAccessPolicyProperties{
				AccessPolicies: []*armkeyvault.AccessPolicyEntry{&accessPolicy},
			},
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to update Azure Key Vault access policy '%s': %w", name, err)
		}
		message.Debug("KeyVault access policies (legacy) configured ")
	}

	// Upgrade Helm installation of the Operator to use workload identity
	helmValues := map[string]interface{}{
		"controllerManager": map[string]interface{}{
			"serviceAccount": map[string]interface{}{
				"annotations": map[string]interface{}{
					"azure.workload.identity/client-id": session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityClientId,
				},
			},
			"podLabels": map[string]interface{}{
				"azure.workload.identity/use": "true",
			},
		},
	}
	_, err = cluster.InstallUpgradeOperator(kubeconfig, operatorNamespace, helmValues)
	if err != nil {
		return fmt.Errorf("failed to upgrade operator: %w", err)
	}

	// Register SecretStore in the cluster
	err = cluster.ApplySecretStore(ctx, kubeconfig, operatorNamespace, humanitecSecretStoreId, &unstructured.Unstructured{
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
				"azurekv": map[string]interface{}{
					"url":      *keyVault.Properties.VaultURI,
					"tenantID": *keyVault.Properties.TenantID,
					"auth":     map[string]interface{}{},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to register secret store, %w", err)
	}

	err = cluster.RestartOperatorDeployment(ctx, kubeconfig, operatorNamespace)
	if err != nil {
		return fmt.Errorf("failed to restart operator deployment, %w", err)
	}

	message.Info("SecretStore configuration applied to the cluster")

	return nil
}

func (p *azureProvider) CleanState(ctx context.Context) error {
	idClient, err := armmsi.NewUserAssignedIdentitiesClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create Managed Identity client, %w", err)
	}

	if session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName != "" {
		message.Info("Managed Identity will be deleted: az identity delete --name %s --resource-group %s",
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName, session.State.AzureProvider.ResourceGroup)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if _, err := idClient.Delete(ctx,
				session.State.AzureProvider.ResourceGroup,
				session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName,
				nil); err != nil {
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete Managed Identity %s, %w", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName, err)
				}
			}
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName = ""
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityClientId = ""
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityPrincipalId = ""
			session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityTenantId = ""
			session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName = ""
			session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName != "" {
		message.Info("Managed Identity will be deleted: az identity delete --name %s --resource-group %s",
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName, session.State.AzureProvider.ResourceGroup)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if _, err := idClient.Delete(ctx,
				session.State.AzureProvider.ResourceGroup,
				session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
				nil); err != nil {
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete Managed Identity %s, %w", session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName, err)
				}
			}
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName = ""
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityClientId = ""
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId = ""
			session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	grClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(p.credential, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return fmt.Errorf("failed to create Graph client, %w", err)
	}

	if session.State.AzureProvider.ConnectCluster.EntraIDGroupId != "" {
		message.Info("Entra ID security group will be deleted: az ad group delete --group %s", session.State.AzureProvider.ConnectCluster.EntraIDGroupId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = grClient.Groups().ByGroupId(session.State.AzureProvider.ConnectCluster.EntraIDGroupId).Delete(ctx, nil); err != nil {
				if strings.Contains(err.Error(), "does not exist") {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete Entra ID group, %w", err)
				}
			}
			session.State.AzureProvider.ConnectCluster.EntraIDGroupId = ""
			session.State.AzureProvider.ConnectCluster.EntraIDGroupName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	return nil
}

func (p *azureProvider) getSubscriptionList(ctx context.Context) ([]string, error) {
	clientFactory, err := armsubscriptions.NewClientFactory(p.credential, nil)
	if err != nil {
		return nil, err
	}
	subList := make([]string, 0)
	pager := clientFactory.NewClient().NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			subList = append(subList, *v.SubscriptionID)
		}
	}
	return subList, nil
}

func (p *azureProvider) getResourceGroups(ctx context.Context, rgClient *armresources.ResourceGroupsClient) ([]string, map[string]string, error) {
	grList := make([]string, 0)
	grRegionMap := make(map[string]string)
	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, v := range page.Value {
			grList = append(grList, *v.Name)
			grRegionMap[*v.Name] = *v.Location
		}
	}
	return grList, grRegionMap, nil
}

func (p *azureProvider) waitManagedIdentityCreated(ctx context.Context, resGroup, name string, idClient *armmsi.UserAssignedIdentitiesClient) error {
	timeout := time.After(60 * time.Second)
	tick := time.Tick(3 * time.Second)
	for loop := true; loop; {
		select {
		case <-timeout:
			return errors.New("timeout")
		case <-tick:
			if _, err := idClient.Get(ctx, resGroup, name, nil); err != nil {
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
					continue
				}
				return err
			}
			loop = false
		}
	}
	return nil
}

func (p *azureProvider) waitFederatedCredentialsCreated(ctx context.Context, resGroup, managedIdentityName, name string, fedClient *armmsi.FederatedIdentityCredentialsClient) error {
	timeout := time.After(60 * time.Second)
	tick := time.Tick(3 * time.Second)
	for loop := true; loop; {
		select {
		case <-timeout:
			return errors.New("timeout")
		case <-tick:
			if _, err := fedClient.Get(ctx, resGroup, managedIdentityName, name, nil); err != nil {
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
					continue
				}
				return err
			}
			loop = false
		}
	}
	return nil
}

func (p *azureProvider) getCluster(ctx context.Context, clusterId string) (*armcontainerservice.ManagedCluster, error) {
	if cluster, ok := p.clusters[clusterId]; ok {
		return cluster, nil
	}
	clientFactory, err := armcontainerservice.NewClientFactory(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client, %w", err)
	}
	resourceGroup, name, err := getAzureResourceGroupAndName(clusterId)
	if err != nil {
		return nil, err
	}
	clusterResp, err := clientFactory.NewManagedClustersClient().Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster, %w", err)
	}
	p.clusters[*clusterResp.ID] = &clusterResp.ManagedCluster
	return p.clusters[*clusterResp.ID], nil
}

func (p *azureProvider) getK8sClient(ctx context.Context, cluster armcontainerservice.ManagedCluster) (*kubernetes.Clientset, error) {
	if k8sClient, ok := p.k8sClients[*cluster.ID]; ok {
		return k8sClient, nil
	}
	clientFactory, err := armcontainerservice.NewClientFactory(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client, %w", err)
	}
	resourceGroup, name, err := getAzureResourceGroupAndName(*cluster.ID)
	if err != nil {
		return nil, err
	}
	res, err := clientFactory.NewManagedClustersClient().ListClusterUserCredentials(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster credentials: %w", err)
	}
	if len(res.Kubeconfigs) == 0 {
		return nil, fmt.Errorf("no kubeconfigs retrieved for cluster %s in resourceGroup %s", resourceGroup, name)
	}
	clientConfig, err := clientcmd.NewClientConfigFromBytes(res.Kubeconfigs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to create client config from kubeconfig: %w", err)
	}
	kubeconfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubeconfig: %w", err)
	}
	p.kubeconfigs[*cluster.ID] = kubeconfig
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate api config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating client set: %w", err)
	}
	p.k8sClients[*cluster.ID] = clientset
	return clientset, nil
}

func (p *azureProvider) createRoleAssignment(ctx context.Context,
	azClient *armauthorization.RoleAssignmentsClient, scope string, properties armauthorization.RoleAssignmentProperties) error {

	roleAssignmentName := uuid.New().String()
	resp, err := azClient.
		Create(ctx, scope, roleAssignmentName, armauthorization.RoleAssignmentCreateParameters{
			Properties: &properties,
		}, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "RoleAssignmentExists" {
			message.Info("Role Assignment already exists")
		} else {
			return fmt.Errorf("failed to create Role Assignment, %w", err)
		}
	} else {
		message.Info("Role Assignment created: %s", *resp.Name)
	}
	return nil
}

func (p *azureProvider) createRoleAssignmentWithRetries(ctx context.Context,
	azClient *armauthorization.RoleAssignmentsClient, scope string, properties armauthorization.RoleAssignmentProperties,
	timeout time.Duration) error {

	timeoutAfter := time.After(timeout)
	ticker := time.NewTicker(5 * time.Second)
	tick := ticker.C
	defer ticker.Stop()

	var err error
	for loop := true; loop; {
		select {
		case <-timeoutAfter:
			return fmt.Errorf("error creating role assignment (retry timeout exceeded), %w", err)
		case <-tick:
			if err = p.createRoleAssignment(ctx, azClient, scope, properties); err != nil {
				message.Debug("error creating role assignment, retrying")
				continue
			}
			loop = false
		}
	}
	return nil
}

func (p *azureProvider) isMicrosoftEntraIDEnabled(ctx context.Context, cluster armcontainerservice.ManagedCluster) (bool, error) {
	kubeconfig, ok := p.kubeconfigs[*cluster.ID]
	if !ok {
		// ensure kubeconfig is created
		if _, err := p.getK8sClient(ctx, cluster); err != nil {
			return false, err
		}
		kubeconfig = p.kubeconfigs[*cluster.ID]
	}
	kubeContext, ok := kubeconfig.Contexts[kubeconfig.CurrentContext]
	if !ok {
		return false, errors.New("invalid kubeconfig: doesn't contain current context")
	}
	user, ok := kubeconfig.AuthInfos[kubeContext.AuthInfo]
	if !ok {
		return false, errors.New("invalid kubeconfig: doesn't contain user from current context")
	}
	exec := user.Exec
	if exec == nil {
		return false, nil
	}
	hasKubelogin := exec.Command == "kubelogin" && strings.Contains(exec.InstallHint, "kubelogin")
	return hasKubelogin, nil
}

func (p *azureProvider) enableIdentityInCluster(ctx context.Context, opCluster armcontainerservice.ManagedCluster, resourceGroup, namespace, sa string) error {
	if opCluster.Properties.SecurityProfile.WorkloadIdentity == nil {
		return fmt.Errorf("cluster must have workload identity enabled")
	}
	if opCluster.Properties.EnableRBAC == nil {
		return fmt.Errorf("cluster must have Azure RBAC enabled")
	}
	if opCluster.Properties.OidcIssuerProfile.IssuerURL == nil {
		return fmt.Errorf("cluster must have OpenID issuer enabled to setup workload identity")
	}

	managedIdentityName := "humanitec-operator-identity"
	federatedCredentialsName := "humanitec-operator-identity"

	idClient, err := armmsi.NewUserAssignedIdentitiesClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create Managed Identity client, %w", err)
	}
	if session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName != "" {
		_, err = idClient.Get(ctx,
			resourceGroup,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
			nil,
		)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				message.Debug("Azure Managed Identity not found: %s, clearing state", session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName)
				session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName = ""
				session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityClientId = ""
				session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId = ""
			} else {
				return fmt.Errorf("failed to check if Managed Identity exists, %w", err)
			}
		} else {
			message.Info("Using Managed Identity from previous session: %s", session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName)
		}
	}
	if session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName == "" {
		message.Info("Creating Managed Identity: az identity create --name %s --resource-group %s", managedIdentityName, resourceGroup)
		resp, err := idClient.CreateOrUpdate(ctx,
			resourceGroup,
			managedIdentityName,
			armmsi.Identity{
				Location: to.Ptr(session.State.AzureProvider.Region),
			},
			nil)
		if err != nil {
			return fmt.Errorf("failed to create Managed Identity, %w", err)
		}
		if err = p.waitManagedIdentityCreated(ctx, resourceGroup, managedIdentityName, idClient); err != nil {
			return fmt.Errorf("error waiting for Managed Identity to be created, %w", err)
		}
		session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName = *resp.Name
		session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityClientId = *resp.Properties.ClientID
		session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityPrincipalId = *resp.Properties.PrincipalID
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}

	fedClient, err := armmsi.NewFederatedIdentityCredentialsClient(session.State.AzureProvider.SubscriptionID, p.credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create Federated Credentials client, %w", err)
	}
	if session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName != "" {
		_, err = fedClient.Get(ctx,
			session.State.AzureProvider.ResourceGroup,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
			session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName,
			nil,
		)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				message.Debug("Azure Federated Credentials not found: %s, clearing state", session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName)
				session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName = ""
			} else {
				return fmt.Errorf("failed to check if Federeted Credentials exist, %w", err)
			}
		} else {
			message.Info("Using Federated Credentials from previous session: %s", session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName)
		}
	}
	if session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName == "" {
		serviceAccount := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, sa)
		message.Info("Creating Federated Identity Credentials: az identity federated-credential create --name %s --identity-name %s --resource-group %s --issuer %s --subject %s --audience api://AzureADTokenExchange",
			federatedCredentialsName,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
			resourceGroup,
			*opCluster.Properties.OidcIssuerProfile.IssuerURL,
			serviceAccount,
		)
		resp, err := fedClient.CreateOrUpdate(ctx,
			resourceGroup,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
			federatedCredentialsName,
			armmsi.FederatedIdentityCredential{
				Properties: &armmsi.FederatedIdentityCredentialProperties{
					Audiences: []*string{to.Ptr("api://AzureADTokenExchange")},
					Issuer:    opCluster.Properties.OidcIssuerProfile.IssuerURL,
					Subject:   &serviceAccount,
				},
			},
			nil)
		if err != nil {
			return fmt.Errorf("failed to create Federated Credentials, %w", err)
		}
		if err = p.waitFederatedCredentialsCreated(ctx,
			resourceGroup,
			session.State.AzureProvider.ConfigureOperatorAccess.ManagedIdentityName,
			federatedCredentialsName,
			fedClient); err != nil {
			return fmt.Errorf("error waiting for Federated Credentials to be created, %w", err)
		}
		session.State.AzureProvider.ConfigureOperatorAccess.FederatedCredentialsName = *resp.Name
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}
	return nil
}
