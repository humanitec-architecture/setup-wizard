package session

type ApplicationSession struct {
	Connect ConnectSession `json:"connect"`
}

type ConnectSession struct {
	HumanitecOrganizationId  string                          `json:"humanitecOrganizationId"`
	CloudProviderId          string                          `json:"cloudProviderId"`
	HumanitecCloudAccountId  string                          `json:"humanitecCloudAccountId"`
	CloudClusterId           string                          `json:"cloudClusterId"`
	CloudLoadBalancerId      string                          `json:"cloudLoadBalancerId"`
	HumanitecClusterId       string                          `json:"humanitecClusterId"`
	DoInstallAgent           *bool                           `json:"doInstallAgent"`
	OperatorNamespace        string                          `json:"operatorNamespace"`
	CloudSecretManagerId     string                          `json:"cloudSecretManagerId"`
	HumanitecSecretStoreId   string                          `json:"humanitecSecretStoreId"`
	LoadBalancers            map[string]string               `json:"loadBalancers"`
	DriverAuthKey            string                          `json:"driverAuthKey"`
	HumanitecApplicationId   string                          `json:"humanitecApplicationId"`
	ContainerRunnerResources ContainerRunnerResourcesSession `json:"containerRunnerResources"`
}

type ContainerRunnerResourcesSession struct {
	ContainerRunnerNamespace                          string `json:"runnerNamespace"`
	ContainerRunnerK8sServiceAccount                  string `json:"runnerServiceAccount"`
	ContainerRunnerK8sRole                            string `json:"runnerK8sRole"`
	ConfigRunnerResourceDefinitionId                  string `json:"configRunnerResourceDefId"`
	OpenTofuContainerRunnerDriverResourceDefinitionId string `json:"containerRunnerDriverResourceDefId"`
}
