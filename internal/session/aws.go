package session

type AwsProviderSession struct {
	CreateCloudIdentity struct {
		ExternalId              string `json:"externalId"`
		RoleArn                 string `json:"roleArn"`
		RoleName                string `json:"roleName"`
		HumanitecCloudAccountId string `json:"resourceAccountId"`
	} `json:"createCloudIdentity"`
	ConnectCluster struct {
		PolicyArn          string `json:"policyArn"`
		PolicyName         string `json:"policyName"`
		K8sRbacGroupName string `json:"k8sClusterRoleName"`
		K8s                *K8s   `json:"k8s"`
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
