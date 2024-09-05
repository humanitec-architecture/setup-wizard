package cloud

import (
	"context"

	"github.com/humanitec/humctl-wizard/internal/platform"
)

type Provider interface {
	GetCallingUserId(ctx context.Context) (string, error)
	SetupProvider(ctx context.Context) error
	CreateCloudIdentity(ctx context.Context, cloudAccountId, cloudAccountName string) (string, error)
	ListClusters(ctx context.Context) ([]string, error)
	ListLoadBalancers(ctx context.Context, clusterId string) ([]string, error)
	ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error)
	IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error)
	WriteKubeConfig(ctx context.Context, clusterId string) (string, error)
	ListSecretManagers() ([]string, error)
	ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error
	IsOperatorInstalled(ctx context.Context) (bool, error)
}
