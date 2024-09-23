package session

type GCPProviderSession struct {
	GPCProject struct {
		ProjectID     string `json:"projectID"`
		ProjectNumber int64  `json:"projectNumber"`
	} `json:"gcpProject"`
	GCPResourcesPostfix string `json:"gcpResourcesPostfix"`
	CloudIdentity       struct {
		WorkloadIdentityPoolName             string `json:"workloadIdentityPoolName"`
		OidcWorkloadIdentityPoolProviderName string `json:"workloadIdentityPoolProviderName"`
		HumanitecServiceAccountUniqueID      string `json:"humanitecServiceAccountUniqueID"`
		HumanitecServiceAccountName          string `json:"humanitecServiceAccountName"`
	} `json:"cloudIdentity"`
	GKEClusters struct {
		ClustersMap      map[string]ClustersInfo
		LoadBalancersMap map[string]LoadBalancerInfo
	} `json:"gkeClusters"`
	ConnectCluster struct {
		IAMCustomRoleName         string `json:"customRoleName"`
		K8sClusterRoleName        string `json:"k8sClusterRoleName"`
		K8sClusterRoleBindingName string `json:"k8sClusterRoleBindingName"`
	} `json:"connectCluster"`
	ConfigureOperatorAccess struct {
		SecretStoreId        string `json:"secretStoreId"`
		IAMRoleSecretManager string `json:"secretManagerIAMRole"`
	} `json:"configureOperatorAccess"`
}

type ClustersInfo struct {
	ID             string `json:"id"`
	Location       string `json:"location"`
	PrivateEnabled bool   `json:"private_enabled"`
	PrivateOnly    bool   `json:"private_only"`
}

type LoadBalancerInfo struct {
	Ip string `json:"ip_address"`
}
