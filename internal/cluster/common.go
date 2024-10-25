package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/kube"
	"helm.sh/helm/v3/pkg/registry"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/humanitec/humctl-wizard/internal/message"
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

const WaitForReadyDeploymentDuration = time.Minute * 2

func WaitForReadyDeployment(ctx context.Context, kubeConfigPath string, namespace string, deployment string) error {
	ctx, cancel := context.WithTimeout(ctx, WaitForReadyDeploymentDuration)
	defer cancel()

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to build kube config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to setup kube client: %w", err)
	}
	dep, err := client.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to find named deployment %s/%s: %w", namespace, deployment, err)
	}
	if dep.Status.ReadyReplicas >= dep.Status.Replicas && dep.Status.Replicas > 0 {
		message.Info("Deployment %s/%s is ready", namespace, deployment)
		return nil
	}
	sb := new(strings.Builder)
	for k, v := range dep.Labels {
		if sb.Len() > 0 {
			sb.WriteRune(',')
		}
		sb.WriteString(k)
		sb.WriteRune('=')
		sb.WriteString(v)
	}
	message.Info("Waiting up to %s until deployment %s/%s is ready", WaitForReadyDeploymentDuration, namespace, deployment)
	watch, err := client.AppsV1().Deployments(namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector: sb.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to watch for deployment %s/%s: %w", namespace, deployment, err)
	}
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
				raw, _ := yaml.Marshal(dep.Status)
				return fmt.Errorf("timed out waiting for readiness, the last status is:\n%s", raw)
			} else {
				return err
			}
		case v := <-watch.ResultChan():
			x := v.Object.(*appsv1.Deployment)
			if x.Name == dep.Name && x.Status.ReadyReplicas >= x.Status.Replicas && x.Status.Replicas > 0 {
				message.Info("Deployment %s/%s is ready", namespace, deployment)
				return nil
			}
		}
	}
}
