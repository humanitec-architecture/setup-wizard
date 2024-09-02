package session

const (
	stateFileName      = ".humctl-wizard-state"
	stateFileDirectory = ".humctl-wizard"
)

var State = Session{}

type Session struct {
	Application ApplicationSession `json:"application"`
	AwsProvider AwsProviderSession `json:"awsProvider"`
	GCPProvider GCPProviderSession `json:"gcpProvider"`
}
