package session

type AwsProviderSession struct {
	CreateCloudIdentity struct {
		ExternalId              string `json:"externalId"`
		RoleArn                 string `json:"roleArn"`
		RoleName                string `json:"roleName"`
		HumanitecCloudAccountId string `json:"resourceAccountId"`
	} `json:"createCloudIdentity"`
	ConnectCluster struct {
		PolicyArn  string `json:"policyArn"`
		PolicyName string `json:"policyName"`
	} `json:"connectCluster"`
	ConfigureOperatorAccess struct {
		AccessSecretsManagerPolicyARN  string `json:"accessSecretManagerPolicyARN"`
		AccessSecretsManagerPolicyName string `json:"accessSecretManagerPolicyName"`
		TrustPolicyRoleARN             string `json:"trustPolicyRoleARN"`
		TrustPolicyRoleName            string `json:"trustPolicyRoleName"`
		PodIdentityAssociationId       string `json:"podIdentityAssociationId"`
		SecretStoreId                  string `json:"secretStoreId"`
	} `json:"configureOperatorAccess"`
}
