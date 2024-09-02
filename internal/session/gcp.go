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
		ClustersMap map[string]ClustersInfo
	} `json:"gkeClusters"`
}

type ClustersInfo struct {
	ID       string `json:"id"`
	Location string `json:"location"`
}
