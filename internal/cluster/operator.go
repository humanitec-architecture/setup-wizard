package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/humanitec/humctl-wizard/internal/keys"

	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
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
	OperatorReleaseName = "humanitec-operator"
)

func InstallUpgradeOperator(kubeConfigPath, namespace string, values map[string]interface{}) (string, error) {
	settings := cli.New()

	registryClient, err := registry.NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create registry client: %w", err)
	}

	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "", namespace), namespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return "", err
	}
	actionConfig.RegistryClient = registryClient

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	_ = os.RemoveAll(path.Join(homeDir, ".humctl-wizard", "humanitec-operator"))

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
	ifInstalled, err := IsOperatorInstalled(kubeConfigPath, namespace)
	if err != nil {
		return "", fmt.Errorf("failed to check if operator is installed: %w", err)
	}

	if values == nil {
		values = map[string]interface{}{}
	}
	if !ifInstalled {
		message.Info("Installing the operator with Helm: helm install %s oci://ghcr.io/humanitec/charts/humanitec-operator --namespace %s --create-namespace",
			OperatorReleaseName, namespace)
		client := action.NewInstall(actionConfig)
		client.Wait = true
		client.CreateNamespace = true
		client.ReleaseName = OperatorReleaseName
		client.Namespace = namespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(chart, values)
		if err != nil {
			return "", fmt.Errorf("failed to install operator: %w", err)
		}
	} else {
		message.Info("Upgrading the operator with Helm: helm upgrade %s oci://ghcr.io/humanitec/charts/humanitec-operator --namespace %s",
			OperatorReleaseName, namespace)
		client := action.NewUpgrade(actionConfig)
		client.Wait = true
		client.Wait = true
		client.Namespace = namespace
		client.Timeout = 5 * time.Minute

		release, err = client.Run(OperatorReleaseName, chart, values)
		if err != nil {
			return "", fmt.Errorf("failed to upgrade operator: %w", err)
		}
	}

	return fmt.Sprintf("%s - %d", release.Name, release.Version), nil
}

func IsOperatorInstalled(kubeConfigPath, namespace string) (bool, error) {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(kubeConfigPath, "", namespace), namespace, os.Getenv("HELM_DRIVER"), func(format string, args ...interface{}) {
		message.Debug(format, args...)
	}); err != nil {
		return false, fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}

	histClient := action.NewHistory(actionConfig)
	histClient.Max = 1

	_, err := histClient.Run(OperatorReleaseName)
	if err != nil {
		if err == driver.ErrReleaseNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get history: %w", err)
	}
	return true, nil
}

func UninstallOperator(kubeConfigPath, namespace string) error {
	return UninstallChart(kubeConfigPath, OperatorReleaseName, namespace)
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

	message.Info("Creating SecretStore resource in the cluster: %s", secretsStoreId)
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

func ConfigureDriverAuth(ctx context.Context, kubeconfig, namespace string, platform *platform.HumanitecPlatform) error {
	isSecretExists, err := IsSecretExists(ctx, kubeconfig, namespace, "humanitec-operator-private-key")
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	if isSecretExists && session.State.Application.Connect.DriverAuthKey != "" {
		useExisting, err := message.BoolSelect("The operator already configured to authenticate Humanitec drivers. Would you like to use the existing configuration?")
		if err != nil {
			return fmt.Errorf("failed to select an option: %w", err)
		}
		if useExisting {
			return nil
		}
	}

	if session.State.Application.Connect.DriverAuthKey != "" {
		// Delete old key
		resp, err := platform.Client.DeletePublicKeyWithResponse(ctx,
			session.State.Application.Connect.HumanitecOrganizationId,
			session.State.Application.Connect.DriverAuthKey)
		if err != nil {
			return fmt.Errorf("failed to delete old public key: %w", err)
		}
		if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
			return fmt.Errorf("failed to delete public key, status code: %d", resp.StatusCode())
		}
	}

	// Generate private/public key pair
	keyPair, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	keyPEM := keyPair.Private
	pubPEM := keyPair.Public

	// Create K8s Secret containing the private key
	data := map[string]string{
		"privateKey":              string(keyPEM),
		"humanitecOrganisationID": session.State.Application.Connect.HumanitecOrganizationId,
	}
	message.Info("Creating K8s Secret containing private key: humanitec-operator-private-key")
	if err = ApplySecret(ctx, kubeconfig, namespace, "humanitec-operator-private-key", data); err != nil {
		return fmt.Errorf("failed to create private key secret: %w", err)
	}

	// Register public key in the orchestrator
	message.Info("Registering public key in Humanitec")
	body, err := json.Marshal(string(pubPEM))
	if err != nil {
		return fmt.Errorf("failed to selialize public key: %w", err)
	}
	resp, err := platform.Client.CreatePublicKeyWithBodyWithResponse(ctx, platform.OrganizationId, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to register public key: %w", err)
	}
	if resp.JSON400 != nil {
		return fmt.Errorf("failed to register public key, status code: %s, message: %s", resp.Status(), resp.JSON400.Message)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to register public key, status code: %s", resp.Status())
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("failed to register public key, invalid response body: %s", string(resp.Body))
	}
	session.State.Application.Connect.DriverAuthKey = resp.JSON200.Id
	if err := session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}
