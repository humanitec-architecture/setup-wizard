package cloud

import (
	"context"

	"github.com/humanitec/humctl-wizard/internal/platform"
)

type providerFactoryFunc func(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (Provider, error)

func GetProvidersFactory() map[string]providerFactoryFunc {
	return map[string]providerFactoryFunc{
		"aws":   newAwsProvider,
		"gcp":   NewGCPProvider,
		"azure": NewAzureProvider,
	}
}
