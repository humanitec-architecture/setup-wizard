package session

type ApplicationSession struct {
	Connect ConnectSession `json:"connect"`
}

type ConnectSession struct {
	HumanitecOrganizationId string `json:"humanitecOrganizationId"`
	CloudProviderId         string `json:"cloudProviderId"`
	HumanitecCloudAccountId string `json:"humanitecCloudAccountId"`
	CloudClusterId          string `json:"cloudClusterId"`
	CloudLoadBalancerId     string `json:"cloudLoadBalancerId"`
	HumanitecClusterId      string `json:"humanitecClusterId"`
	DoInstallAgent          *bool  `json:"doInstallAgent"`
	DoInstallOperator       *bool  `json:"doInstallOperator"`
	OperatorNamespace       string `json:"operatorNamespace"`
	CloudSecretManagerId    string `json:"cloudSecretManagerId"`
	HumanitecSecretStoreId  string `json:"humanitecSecretStoreId"`
}
