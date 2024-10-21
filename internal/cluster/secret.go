package cluster

import (
	"context"
	"fmt"

	apiCorev1 "k8s.io/api/core/v1"
	k8s_apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func ApplySecret(ctx context.Context, kubeConfigPath, namespace, secretName string, secretData map[string]string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to build kube config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	secretClinet := client.CoreV1().Secrets(namespace)

	kind := "Secret"
	apiVersion := "v1"
	secretType := apiCorev1.SecretType("Opaque")
	_, err = secretClinet.Apply(ctx, &corev1.SecretApplyConfiguration{
		TypeMetaApplyConfiguration: v1.TypeMetaApplyConfiguration{
			Kind:       &kind,
			APIVersion: &apiVersion,
		},
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{
			Name:      &secretName,
			Namespace: &namespace,
		},
		StringData: secretData,
		Type:       &secretType,
	}, metav1.ApplyOptions{
		FieldManager: "humctl-wizard",
	})

	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}
	return nil
}

func IsSecretExists(ctx context.Context, kubeConfigPath, namespace, secretName string) (bool, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return false, fmt.Errorf("failed to build kube config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	secretClinet := client.CoreV1().Secrets(namespace)

	_, err = secretClinet.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8s_apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get secret: %w", err)
	}
	return true, nil
}
