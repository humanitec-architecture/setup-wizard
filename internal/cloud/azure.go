package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/golang-jwt/jwt/v5"
	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
)

type azureProvider struct {
	credential        azcore.TokenCredential
	humanitecPlatform *platform.HumanitecPlatform
}

func NewAzureProvider(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (Provider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load azure default credentials, %w", err)
	}

	return &azureProvider{
		credential:        cred,
		humanitecPlatform: humanitecPlatform,
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
			} else {
				return "", fmt.Errorf("failed to check if Managed Identity exists, %w", err)
			}
		} else {
			message.Info("Using Managed Identity from previous session: %s", session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName)
		}
	}

	if session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName == "" {
		resourceName, err := message.Prompt("Enter a name for new Managed Identity:", "my-azure-cloud-account")
		if err != nil {
			return "", fmt.Errorf("failed to select Managed Identity name: %w", err)
		}
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
		message.Info("Managed Identity created: %s", *resp.Identity.Name)
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityName = *resp.Identity.Name
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityClientId = *resp.Identity.Properties.ClientID
		session.State.AzureProvider.CreateCloudIdentity.ManagedIdentityTenantId = *resp.Identity.Properties.TenantID
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
		message.Info("Federated Credentials created: %s", *resp.FederatedIdentityCredential.Name)
		session.State.AzureProvider.CreateCloudIdentity.FederatedCredentialsName = *resp.FederatedIdentityCredential.Name
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
		message.Info("Humanitec Cloud Account created: %s", humanitecCloudAccountId)
	} else {
		message.Info("Humanitec Cloud Account already created, loading from state: %s", session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId)
		if err := checkResourceAccount(ctx, p.humanitecPlatform.Client, p.humanitecPlatform.OrganizationId, humanitecCloudAccountId); err != nil {
			return "", fmt.Errorf("failed to test existing resource account, %w", err)
		}
	}

	return session.State.AzureProvider.CreateCloudIdentity.HumanitecCloudAccountId, nil
}

func (p *azureProvider) ListClusters(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (p *azureProvider) ListLoadBalancers(ctx context.Context, clusterId string) ([]string, error) {
	return []string{}, nil
}

func (p *azureProvider) ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error) {
	return "", nil
}

func (p *azureProvider) IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error) {
	return false, nil
}

func (p *azureProvider) WriteKubeConfig(ctx context.Context, clusterId string) (string, error) {
	return "", nil
}

func (p *azureProvider) ListSecretManagers() ([]string, error) {
	return []string{}, nil
}

func (p *azureProvider) ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error {
	return nil
}

func (p *azureProvider) IsOperatorInstalled(ctx context.Context) (bool, error) {
	return false, nil
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
