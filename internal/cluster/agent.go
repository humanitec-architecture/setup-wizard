package cluster

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/humanitec/humctl-wizard/internal/message"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/kube"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/storage/driver"
)

const (
	AgentReleaseName = "humanitec-agent"
	AgentNamespace   = "humanitec-agent"
)

func InstallAgent(humanitecOrg, privateKey, kubeConfigPath string) (string, error) {
	settings := cli.New()

	registryClient, err := registry.NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create registry client: %w", err)
	}

	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "", AgentNamespace), AgentNamespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return "", err
	}
	actionConfig.RegistryClient = registryClient

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	_ = os.RemoveAll(path.Join(homeDir, ".humctl-wizard", "humanitec-agent"))

	actionPull := action.NewPullWithOpts(action.WithConfig(actionConfig))
	actionPull.Settings = settings
	actionPull.DestDir = path.Join(homeDir, ".humctl-wizard")
	actionPull.Untar = true
	actionPull.UntarDir = actionPull.DestDir
	_, err = actionPull.Run("oci://ghcr.io/humanitec/charts/humanitec-agent")
	if err != nil {
		return "", fmt.Errorf("failed to pull chart: %w", err)
	}

	chart, err := loader.LoadDir(path.Join(actionPull.UntarDir, "humanitec-agent"))
	if err != nil {
		return "", fmt.Errorf("failed to load chart: %w", err)
	}

	var release *release.Release
	ifInstalled, err := IsAgentInstalled(kubeConfigPath)
	if err != nil {
		return "", fmt.Errorf("failed to check if agent is installed: %w", err)
	}

	if !ifInstalled {
		message.Info("Installing the agent with Helm: helm install %s oci://ghcr.io/humanitec/charts/humanitec-agent --namespace %s --create-namespace",
			AgentReleaseName, AgentNamespace)
		client := action.NewInstall(actionConfig)
		client.Wait = true
		client.CreateNamespace = true
		client.ReleaseName = AgentReleaseName
		client.Namespace = AgentNamespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(chart, map[string]interface{}{
			"humanitec": map[string]any{
				"org":        humanitecOrg,
				"privateKey": privateKey,
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to install agent: %w", err)
		}
	} else {
		message.Info("Upgrading the agent with Helm: helm upgrade %s oci://ghcr.io/humanitec/charts/humanitec-agent --namespace %s",
			AgentReleaseName, AgentNamespace)
		client := action.NewUpgrade(actionConfig)
		client.Wait = true
		client.Wait = true
		client.Namespace = AgentNamespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(AgentReleaseName, chart, map[string]interface{}{
			"humanitec": map[string]any{
				"org":        humanitecOrg,
				"privateKey": privateKey,
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to upgrade agent: %w", err)
		}
	}

	return fmt.Sprintf("%s - %d", release.Name, release.Version), nil
}

func IsAgentInstalled(kubeConfigPath string) (bool, error) {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "", AgentNamespace), AgentNamespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return false, fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}

	histClient := action.NewHistory(actionConfig)
	histClient.Max = 1

	_, err := histClient.Run(AgentReleaseName)
	if err != nil {
		if err == driver.ErrReleaseNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get history: %w", err)
	}
	return true, nil
}

func UninstallAgent(kubeConfigPath string) error {
	return UninstallChart(kubeConfigPath, AgentReleaseName, AgentNamespace)
}
