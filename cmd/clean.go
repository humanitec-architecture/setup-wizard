package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/humanitec/humctl-wizard/internal/cloud"
	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/spf13/cobra"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean resources created by the wizard",
	Long:  `It cleans Cloud and Humanitec resources created by the wizard and stored in the state.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		err := session.Load(true)
		if err != nil {
			return fmt.Errorf("failed to load session: %v", err)
		}

		humanitecPlatform, err := initializeHumanitecPlatform(ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize humanitec platform: %w", err)
		}

		var provider cloud.Provider
		providersFactory := cloud.GetProvidersFactory()
		if session.State.Application.Connect.CloudProviderId != "" {
			provider, err = providersFactory[session.State.Application.Connect.CloudProviderId](ctx, humanitecPlatform)
			if err != nil {
				return fmt.Errorf("failed to create cloud provider: %w", err)
			}
		}

		if err := Clean(ctx, humanitecPlatform, provider); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}

func Clean(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, provider cloud.Provider) error {
	if provider == nil {
		message.Success("provider not initialized, no resources to clean")
	}

	if err := deleteHumanitecResources(ctx, humanitecPlatform); err != nil {
		return fmt.Errorf("failed to remove humanitec resources: %w", err)
	}

	if err := provider.CleanState(ctx); err != nil {
		return fmt.Errorf("failed to clean resources: %w", err)
	}

	clusterId := session.State.Application.Connect.CloudClusterId
	if clusterId != "" {
		kubeConfigPath, err := provider.WriteKubeConfig(ctx, clusterId)
		if err != nil {
			return fmt.Errorf("failed to get kubeconfig: %w", err)
		}
		if err = deleteK8sResources(ctx, kubeConfigPath); err != nil {
			return fmt.Errorf("failed to remove k8s resources: %w", err)
		}
	}

	if err := session.Reset(); err != nil {
		return fmt.Errorf("failed to reset session: %w", err)
	}

	message.Success("All resources are removed")
	return nil
}

func deleteHumanitecResources(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) error {
	if session.State.Application.Connect.HumanitecApplicationId != "" {
		message.Info("Humanitec Application will be deleted: %s", session.State.Application.Connect.HumanitecApplicationId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			resp, err := humanitecPlatform.Client.DeleteApplicationWithResponse(ctx,
				session.State.Application.Connect.HumanitecOrganizationId,
				session.State.Application.Connect.HumanitecApplicationId)
			if err != nil {
				return fmt.Errorf("failed to delete application: %w", err)
			}
			if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("failed to delete application, status code: %d, response: %s", resp.StatusCode(), string(resp.Body))
			}
			session.State.Application.Connect.HumanitecApplicationId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	clusterDeleted, agentDeleted := false, false
	if session.State.Application.Connect.HumanitecClusterId != "" {
		message.Info("Humanitec Resource Definition (k8s-cluster) will be deleted: %s", session.State.Application.Connect.HumanitecClusterId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = deleteResourceDefinition(ctx, humanitecPlatform, session.State.Application.Connect.HumanitecClusterId); err != nil {
				return err
			}
			clusterDeleted = true
		}

		agentID := "agent-" + session.State.Application.Connect.HumanitecClusterId
		message.Info("Humanitec Resource Definition (agent) will be deleted: %s", agentID)
		proceed, err = message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = deleteResourceDefinition(ctx, humanitecPlatform, agentID); err != nil {
				return err
			}
			agResp, err := humanitecPlatform.Client.DeleteAgentWithResponse(ctx,
				session.State.Application.Connect.HumanitecOrganizationId,
				agentID)
			if err != nil {
				return fmt.Errorf("failed to delete agent resource definition: %w", err)
			}
			if agResp.StatusCode() != http.StatusOK && agResp.StatusCode() != http.StatusNoContent && agResp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("failed to delete agent resource definition, status code: %d, response: %s", agResp.StatusCode(), string(agResp.Body))
			}
			agentDeleted = true
		}

		if clusterDeleted && agentDeleted {
			session.State.Application.Connect.HumanitecClusterId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if tfRunnerDriverDefId := session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId; tfRunnerDriverDefId != "" {
		message.Info("Humanitec Resource Definition (humanitec/terraform-runner) will be deleted: %s", tfRunnerDriverDefId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = deleteResourceDefinition(ctx, humanitecPlatform, tfRunnerDriverDefId); err != nil {
				return err
			}
			session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if configRunnerDefId := session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId; configRunnerDefId != "" {
		message.Info("Humanitec Resource Definition (echo config runner) will be deleted: %s", configRunnerDefId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = deleteResourceDefinition(ctx, humanitecPlatform, configRunnerDefId); err != nil {
				return err
			}
			session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.Application.Connect.HumanitecCloudAccountId != "" {
		message.Info("Humanitec Cloud Account will be deleted: %s", session.State.Application.Connect.HumanitecCloudAccountId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			resp, err := humanitecPlatform.Client.DeleteResourceAccountWithResponse(ctx,
				session.State.Application.Connect.HumanitecOrganizationId,
				session.State.Application.Connect.HumanitecCloudAccountId)
			if err != nil {
				return fmt.Errorf("failed to delete cloud account: %w", err)
			}
			if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("failed to delete cloud account, status code: %d, response: %s", resp.StatusCode(), string(resp.Body))
			}
			session.State.Application.Connect.HumanitecCloudAccountId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.Application.Connect.HumanitecSecretStoreId != "" {
		message.Info("Humanitec Secret Store will be deleted: %s", session.State.Application.Connect.HumanitecSecretStoreId)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			resp, err := humanitecPlatform.Client.DeleteOrgsOrgIdSecretstoresStoreIdWithResponse(ctx,
				session.State.Application.Connect.HumanitecOrganizationId,
				session.State.Application.Connect.HumanitecSecretStoreId)
			if err != nil {
				return fmt.Errorf("failed to delete secret store: %w", err)
			}
			if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("failed to delete secret store, status code: %d, response: %s", resp.StatusCode(), string(resp.Body))
			}
			session.State.Application.Connect.HumanitecCloudAccountId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.Application.Connect.DriverAuthKey != "" {
		message.Info("Public key for authenticating drivers will be removed from Humanitec: %s", session.State.Application.Connect.DriverAuthKey)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			resp, err := humanitecPlatform.Client.DeletePublicKeyWithResponse(ctx,
				session.State.Application.Connect.HumanitecOrganizationId,
				session.State.Application.Connect.DriverAuthKey)
			if err != nil {
				return fmt.Errorf("failed to delete public key: %w", err)
			}
			if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusNotFound {
				return fmt.Errorf("failed to delete public key, status code: %d, response: %s", resp.StatusCode(), string(resp.Body))
			}
			session.State.Application.Connect.DriverAuthKey = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	return nil
}

func deleteK8sResources(ctx context.Context, kubeConfigPath string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create a client from kubeconfig: %w", err)
	}

	// We have different implementations to store K8s state for different providers
	var clusterRoleName *string
	var clusterRoleBindingName *string
	switch session.State.Application.Connect.CloudProviderId {
	case "aws":
		if session.State.AwsProvider.ConnectCluster.K8s != nil {
			clusterRoleName = &session.State.AwsProvider.ConnectCluster.K8s.ClusterRoleName
			clusterRoleBindingName = &session.State.AwsProvider.ConnectCluster.K8s.ClusterRoleBindingName
		}
	case "gcp":
		clusterRoleName = &session.State.GCPProvider.ConnectCluster.K8sClusterRoleName
		clusterRoleBindingName = &session.State.GCPProvider.ConnectCluster.K8sClusterRoleBindingName
	case "azure":
		if session.State.AzureProvider.ConnectCluster.K8s != nil {
			clusterRoleName = &session.State.AzureProvider.ConnectCluster.K8s.ClusterRoleName
			clusterRoleBindingName = &session.State.AzureProvider.ConnectCluster.K8s.ClusterRoleBindingName
		}
	}

	terraformRunnerNamespace := session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerNamespace
	if terraformRunnerNamespace != "" {
		if terraformRunnerServiceAccount := session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sServiceAccount; terraformRunnerServiceAccount != "" {
			message.Info("Terraform runner service account '%s' will be deleted from K8s cluster namespace '%s'", terraformRunnerServiceAccount, terraformRunnerNamespace)
			proceed, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to get user input: %w", err)
			}
			if proceed {
				if err = clientset.CoreV1().ServiceAccounts(terraformRunnerNamespace).Delete(ctx, terraformRunnerServiceAccount, metav1.DeleteOptions{}); err != nil {
					var sErr *kerrors.StatusError
					if errors.As(err, &sErr) && sErr.ErrStatus.Code == 404 {
						message.Info("k8s service account '%s' already deleted", terraformRunnerServiceAccount)
					} else {
						return fmt.Errorf("failed to delete k8s service account '%s': %w", terraformRunnerServiceAccount, err)
					}
				} else {
					message.Debug("k8s service account '%s' deleted", terraformRunnerServiceAccount)
				}
				session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sServiceAccount = ""
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			}
		}

		if k8sTerraformRunnerRole := session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sRole; k8sTerraformRunnerRole != "" {
			message.Info("Terraform runner k8s role '%s' will be deleted from K8s cluster namespace '%s'", k8sTerraformRunnerRole, terraformRunnerNamespace)
			proceed, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to get user input: %w", err)
			}
			if proceed {
				if err = clientset.RbacV1().Roles(terraformRunnerNamespace).Delete(ctx, k8sTerraformRunnerRole, metav1.DeleteOptions{}); err != nil {
					var sErr *kerrors.StatusError
					if errors.As(err, &sErr) && sErr.ErrStatus.Code == 404 {
						message.Info("k8s role '%s' already deleted", k8sTerraformRunnerRole)
					} else {
						return fmt.Errorf("failed to delete k8s role '%s': %w", k8sTerraformRunnerRole, err)
					}
				} else {
					message.Debug("k8s role '%s' deleted", k8sTerraformRunnerRole)
				}
				session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sRole = ""
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			}
		}

		message.Info("Terraform runner namespace '%s' will be deleted from K8s cluster", terraformRunnerNamespace)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = clientset.CoreV1().Namespaces().Delete(ctx, terraformRunnerNamespace, metav1.DeleteOptions{}); err != nil {
				var sErr *kerrors.StatusError
				if errors.As(err, &sErr) && sErr.ErrStatus.Code == 404 {
					message.Info("namespace '%s' already deleted", terraformRunnerNamespace)
				} else {
					return fmt.Errorf("failed to delete namespace '%s': %w", terraformRunnerNamespace, err)
				}
			} else {
				message.Debug("namespace '%s' deleted", terraformRunnerNamespace)
			}
			session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerNamespace = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if clusterRoleBindingName != nil && *clusterRoleBindingName != "" {
		message.Info("Cluster Role Binding will be deleted from K8s cluster: %s", *clusterRoleBindingName)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = clientset.RbacV1().ClusterRoleBindings().Delete(ctx, *clusterRoleBindingName, metav1.DeleteOptions{}); err != nil {
				if kerrors.IsNotFound(err) {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete cluster role binding: %w", err)
				}
			}
			*clusterRoleBindingName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if clusterRoleName != nil && *clusterRoleName != "" {
		message.Info("Cluster Role will be deleted from K8s cluster: %s", *clusterRoleName)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = clientset.RbacV1().ClusterRoles().Delete(ctx, *clusterRoleName, metav1.DeleteOptions{}); err != nil {
				if kerrors.IsNotFound(err) {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete cluster role: %w", err)
				}
			}
			*clusterRoleName = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	isAgentInstalled, err := cluster.IsAgentInstalled(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to check if agent is installed: %w", err)
	}
	if isAgentInstalled {
		message.Info("Humanitec Agent will be uninstalled from K8s cluster: helm uninstall %s --namespace %s", cluster.AgentReleaseName, cluster.AgentNamespace)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = cluster.UninstallAgent(kubeConfigPath); err != nil {
				return fmt.Errorf("failed to uninstall agent: %w", err)
			}
		}

		message.Info("Namespace will be deleted from K8s cluster: %s", cluster.AgentNamespace)
		proceed, err = message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = clientset.CoreV1().Namespaces().Delete(ctx, cluster.AgentNamespace, metav1.DeleteOptions{}); err != nil {
				if kerrors.IsNotFound(err) {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete namespace: %w", err)
				}
			}
		}
	}

	isOperatorInstalled, err := cluster.IsOperatorInstalled(kubeConfigPath, session.State.Application.Connect.OperatorNamespace)
	if err != nil {
		return fmt.Errorf("failed to check if operator is installed: %w", err)
	}
	if isOperatorInstalled {
		message.Info("Humanitec Operator will be uninstalled from K8s cluster: helm uninstall %s --namespace %s", cluster.OperatorReleaseName, session.State.Application.Connect.OperatorNamespace)
		proceed, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = cluster.UninstallOperator(kubeConfigPath, session.State.Application.Connect.OperatorNamespace); err != nil {
				return fmt.Errorf("failed to uninstall operator: %w", err)
			}
		}

		message.Info("Namespace will be deleted from K8s cluster: %s", session.State.Application.Connect.OperatorNamespace)
		proceed, err = message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		}
		if proceed {
			if err = clientset.CoreV1().Namespaces().Delete(ctx, session.State.Application.Connect.OperatorNamespace, metav1.DeleteOptions{}); err != nil {
				if kerrors.IsNotFound(err) {
					message.Info("The resource doesn't exist or has been already removed")
				} else {
					return fmt.Errorf("failed to delete namespace: %w", err)
				}
			}
			session.State.Application.Connect.OperatorNamespace = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	return nil
}

func deleteResourceDefinition(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, defId string) error {
	// As resource cleanup takes some time, we need to delete active resources first
	resp, err := humanitecPlatform.Client.ListActiveResourceByDefinitionWithResponse(ctx,
		session.State.Application.Connect.HumanitecOrganizationId,
		defId)
	if err != nil {
		return fmt.Errorf("failed to list active resources by definition %s: %w", defId, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to list active resources by definition %s, status code: %d", defId, resp.StatusCode())
	}
	for _, resource := range *resp.JSON200 {
		arResp, err := humanitecPlatform.Client.DeleteActiveResourceWithResponse(ctx,
			resource.OrgId,
			resource.AppId,
			resource.EnvId,
			resource.Type+"."+resource.Class,
			resource.ResId,
			nil)
		if err != nil {
			return fmt.Errorf("failed to delete active resource: %w", err)
		}
		if arResp.StatusCode() != http.StatusOK && arResp.StatusCode() != http.StatusNoContent && arResp.StatusCode() != http.StatusNotFound {
			return fmt.Errorf("failed to delete active resource, status code: %d", resp.StatusCode())
		}
	}

	defResp, err := humanitecPlatform.Client.DeleteResourceDefinitionWithResponse(ctx,
		session.State.Application.Connect.HumanitecOrganizationId,
		defId,
		nil)
	if err != nil {
		return fmt.Errorf("failed to delete resource definition: %w", err)
	}
	if defResp.StatusCode() != http.StatusOK && defResp.StatusCode() != http.StatusNoContent && defResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("failed to delete resource definition, status code: %d", resp.StatusCode())
	}
	return nil
}
