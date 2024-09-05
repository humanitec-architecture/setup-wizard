package session

type AzureProviderSession struct {
	SubscriptionID      string
	ResourceGroup       string
	Region              string
	CreateCloudIdentity struct {
		HumanitecCloudAccountId  string `json:"humanitecCloudAccountId"`
		ManagedIdentityName      string `json:"managedIdentityName"`
		ManagedIdentityClientId  string `json:"managedIdentityClientId"`
		ManagedIdentityTenantId  string `json:"managedIdentityTenantId"`
		FederatedCredentialsName string `json:"federatedCredentialsName"`
	}
}
