package cluster

import (
	"fmt"
	"os"
	"strings"

	"github.com/humanitec/humctl-wizard/internal/message"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/kube"
	"helm.sh/helm/v3/pkg/registry"
)

func UninstallChart(kubeConfigPath, release, namespace string) error {
	registryClient, err := registry.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}

	actionConfig := new(action.Configuration)
	if err = actionConfig.Init(kube.GetConfig(kubeConfigPath, "", namespace), namespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return err
	}
	actionConfig.RegistryClient = registryClient

	client := action.NewUninstall(actionConfig)
	if _, err = client.Run(release); err != nil {
		if strings.HasPrefix(err.Error(), "uninstall: Release not loaded:") {
			message.Info("Helm release %s is not installed", release)
		} else {
			return fmt.Errorf("failed to uninstall agent: %w", err)
		}
	}
	return nil
}
