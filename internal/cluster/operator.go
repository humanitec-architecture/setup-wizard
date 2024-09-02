package cluster

import (
	"context"
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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	operatorReleaseName = "humanitec-operator"
)

func InstallOperator(humanitecOrg, kubeConfigPath, namespace string) (string, error) {
	settings := cli.New()

	registryClient, err := registry.NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create registry client: %w", err)
	}

	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "context", namespace), namespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return "", err
	}
	actionConfig.RegistryClient = registryClient

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	os.RemoveAll(path.Join(homeDir, ".humctl-wizard", "humanitec-operator"))

	actionPull := action.NewPullWithOpts(action.WithConfig(actionConfig))
	actionPull.Settings = settings
	actionPull.DestDir = path.Join(homeDir, ".humctl-wizard")
	actionPull.Untar = true
	actionPull.UntarDir = actionPull.DestDir
	_, err = actionPull.Run("oci://ghcr.io/humanitec/charts/humanitec-operator")
	if err != nil {
		return "", fmt.Errorf("failed to pull chart: %w", err)
	}

	chart, err := loader.LoadDir(path.Join(actionPull.UntarDir, "humanitec-operator"))
	if err != nil {
		return "", fmt.Errorf("failed to load chart: %w", err)
	}

	var release *release.Release
	ifInstalled, err := isOperatorInstalled(kubeConfigPath, namespace)
	if err != nil {
		return "", fmt.Errorf("failed to check if operator is installed: %w", err)
	}

	if !ifInstalled {
		client := action.NewInstall(actionConfig)
		client.Wait = true
		client.CreateNamespace = true
		client.ReleaseName = operatorReleaseName
		client.Namespace = namespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(chart, map[string]interface{}{})
		if err != nil {
			return "", fmt.Errorf("failed to install operator: %w", err)
		}
	} else {
		client := action.NewUpgrade(actionConfig)
		client.Wait = true
		client.Wait = true
		client.Namespace = namespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(operatorReleaseName, chart, map[string]interface{}{})
		if err != nil {
			return "", fmt.Errorf("failed to upgrade operator: %w", err)
		}
	}

	return fmt.Sprintf("%s - %d", release.Name, release.Version), nil
}

func isOperatorInstalled(kubeConfigPath, namespace string) (bool, error) {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "context", namespace), namespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return false, fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}

	histClient := action.NewHistory(actionConfig)
	histClient.Max = 1

	_, err := histClient.Run(operatorReleaseName)
	if err != nil {
		if err == driver.ErrReleaseNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get history: %w", err)
	}
	return true, nil
}

func RestartOperatorDeployment(ctx context.Context, kubeConfigPath, namespace string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to build kube config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	deploymentsClient := client.AppsV1().Deployments(namespace)
	data := fmt.Sprintf(`{"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": "%s"}}}}}`, time.Now().Format("20060102150405"))
	_, err = deploymentsClient.Patch(ctx, "humanitec-operator-controller-manager", types.StrategicMergePatchType, []byte(data), v1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch deployment: %w", err)
	}
	return nil
}

func ApplySecretStore(ctx context.Context, kubeconfig, namespace, secretsStoreId string, object *unstructured.Unstructured) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kube config: %w", err)
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	object.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "humanitec.io",
		Version: "v1alpha1",
		Kind:    "SecretStore",
	})
	_, err = client.Resource(schema.GroupVersionResource{
		Group:    "humanitec.io",
		Version:  "v1alpha1",
		Resource: "secretstores",
	}).Namespace(namespace).Apply(ctx, secretsStoreId, object, v1.ApplyOptions{
		FieldManager: "humctl-wizard",
	})
	if err != nil {
		return fmt.Errorf("failed to an object: %w", err)
	}
	return nil
}
