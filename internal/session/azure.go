package session

type AzureProviderSession struct {
	SubscriptionID      string
	ResourceGroup       string
	Region              string
	CreateCloudIdentity struct {
		HumanitecCloudAccountId    string `json:"humanitecCloudAccountId"`
		ManagedIdentityName        string `json:"managedIdentityName"`
		ManagedIdentityClientId    string `json:"managedIdentityClientId"`
		ManagedIdentityTenantId    string `json:"managedIdentityTenantId"`
		ManagedIdentityPrincipalId string `json:"managedIdentityPrincipalId"`
		FederatedCredentialsName   string `json:"federatedCredentialsName"`
	}
	ConnectCluster struct {
		LoadBalancerName string `json:"loadBalancerName"`
		EntraIDGroupName string `json:"entraIDGroupName"`
		EntraIDGroupId   string `json:"entraIDGroupId"`
		K8s              *K8s   `json:"k8s"`
	}
	ConfigureOperatorAccess struct {
		SecretStoreId              string `json:"secretStoreId"`
		ManagedIdentityName        string `json:"managedIdentityName"`
		ManagedIdentityClientId    string `json:"managedIdentityId"`
		ManagedIdentityPrincipalId string `json:"managedPrincipalId"`
		FederatedCredentialsName   string `json:"federatedCredentialsName"`
	}
}
