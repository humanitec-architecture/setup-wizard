package cmd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	k8s_rbac "k8s.io/api/rbac/v1"

	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/humanitec/humctl-wizard/internal/cloud"
	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/keys"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/humanitec/humctl-wizard/internal/utils"
)

var clusterTypeDriverMap = map[string]string{
	"humanitec/k8s-cluster-aks": "aks",
	"humanitec/k8s-cluster-eks": "eks",
	"humanitec/k8s-cluster-gke": "gke",
	"humanitec/k8s-cluster":     "k8s",
}

const (
	tfRunnerConfigResId = "tf-runner"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect humanitec to an existing cloud resources",
	Long:  `It will guide you through the process of connecting an existing cloud resources to Humanitec.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		err := session.Load(false)
		if err != nil {
			return fmt.Errorf("failed to load session: %v", err)
		}

		humanitecPlatform, err := initializeHumanitecPlatformAndSaveSession(ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize humanitec platform: %w", err)
		}

		provider, err := selectCloudProvider(ctx, humanitecPlatform)
		if err != nil {
			return fmt.Errorf("failed to select cloud provider: %w", err)
		}

		cloudAccountId, err := createCloudIdentity(ctx, provider, humanitecPlatform)
		if err != nil {
			return fmt.Errorf("failed to create cloud identity: %w", err)
		}

		clusterId, err := getCluster(ctx, provider)
		if err != nil {
			return fmt.Errorf("failed to get cluster: %w", err)
		}

		loadBalancer, err := getLoadBalancer(ctx, provider, clusterId)
		if err != nil {
			return fmt.Errorf("failed to get load balancer: %w", err)
		}

		humanitecClusterId, err := connectCluster(ctx, provider, clusterId, loadBalancer, cloudAccountId)
		if err != nil {
			return fmt.Errorf("failed to connect cluster: %w", err)
		}

		kubeConfigPath, err := provider.WriteKubeConfig(ctx, clusterId)
		if err != nil {
			return fmt.Errorf("failed to write kubeconfig: %w", err)
		}

		message.DocumentationReference(
			"The Humanitec Agent can be used to provide a secure and easy-to-administer way for the Humanitec Platform Orchestrator to access private endpoints in the customer’s infrastructure. It is intended to be run inside the customer’s infrastructure in such a way that it has network connectivity to the necessary systems the Platform Orchestrator needs access to.",
			"https://developer.humanitec.com/integration-and-extensions/humanitec-agent/overview/",
		)
		isAgentInstalled, err := cluster.IsAgentInstalled(kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to check if agent is already installed: %w", err)
		}
		if !isAgentInstalled {
			isClusterPublic, err := provider.IsClusterPubliclyAvailable(ctx, clusterId)
			if err != nil {
				return fmt.Errorf("failed to check if cluster is publicly available: %w", err)
			}

			ifInstallAgent := !isClusterPublic
			if isClusterPublic {
				if session.State.Application.Connect.DoInstallAgent != nil {
					ifInstallAgent = *session.State.Application.Connect.DoInstallAgent
					message.Info("Using previous session value for install agent: %t", ifInstallAgent)
				} else {
					ifInstallAgent, err = message.BoolSelect("Cluster is publicly available. Do you want to install Humanitec Agent anyway?")
					if err != nil {
						return fmt.Errorf("failed to select if install agent: %w", err)
					}
					session.State.Application.Connect.DoInstallAgent = &ifInstallAgent
					if err := session.Save(); err != nil {
						return fmt.Errorf("failed to save session: %w", err)
					}
				}
			}

			if ifInstallAgent {
				if err = installAgent(ctx, humanitecPlatform, humanitecClusterId, kubeConfigPath); err != nil {
					return fmt.Errorf("failed to install agent: %w", err)
				}
				isAgentInstalled = true
				message.Success("Humanitec Agent installed")
			}
		} else {
			message.Success("Humanitec Agent already installed")
		}
		if isAgentInstalled {
			if err = cluster.WaitForReadyDeployment(ctx, kubeConfigPath, cluster.AgentNamespace, "humanitec-agent"); err != nil {
				return fmt.Errorf("agent deployment is not ready: %w", err)
			}
			if err = addAgentToClusterDefinition(ctx, humanitecPlatform, humanitecClusterId); err != nil {
				return fmt.Errorf("failed to update cluster resource definition with agent: %w", err)
			}
		}

		message.DocumentationReference(
			"The Humanitec Operator is a Kubernetes (K8s) operator that controls Deployments made with the Humanitec Platform Orchestrator. Since Humanitec Resources creation can depend on secrets, the Humanitec Operator is also capable of and responsible for provisioning the required Kubernetes Secret resources in the cluster.",
			"https://developer.humanitec.com/integration-and-extensions/humanitec-operator/overview/",
		)

		internalSecrets, err := humanitecPlatform.CheckInternalSecrets(ctx)
		if err != nil {
			return fmt.Errorf("failed to check if resource definitions or shared secrets contain internal values: %w", err)
		}
		if internalSecrets {
			proceedWithOperator, err := message.BoolSelect(`Your organization has some definitions or shared values with secret inputs stored in the Internal Humanitec Secret Store. 
Deployments involving these entities will not work anymore proceeding with the Wizard execution. Do you want to proceed anyway and switch your organization to Operator deployment mode?`)
			if err != nil {
				return fmt.Errorf("failed to select if install operator: %w", err)
			}
			if !proceedWithOperator {
				return errors.New("wizard aborted, Operator mode is the only deployment mode available via Wizard")
			}
		}

		err = installOperator(ctx, humanitecPlatform, provider, kubeConfigPath, clusterId)
		if err != nil {
			return fmt.Errorf("failed to install operator: %w", err)
		}
		message.Success("Humanitec Operator installed")

		message.DocumentationReference(
			"Humanitec Terraform Driver allows you to execute Terraform scripts in a target cluster.",
			"https://developer.humanitec.com/integration-and-extensions/drivers/generic-drivers/terraform/#running-the-terraform-runner-in-a-target-cluster",
		)
		if err = createResourcesForTerraformRunnerExecution(ctx, provider, humanitecPlatform); err != nil {
			return fmt.Errorf("failed to create resources to execute Terraform runner in the cluster: %w", err)
		}

		message.DocumentationReference(
			"The Test Application ensures seamless connectivity between system components, validating integration points as a foundation for further development.",
			"https://github.com/humanitec-architecture/setup-wizard/blob/main/internal/platform/test_workload.score.yaml",
		)

		ifDeployTestApplication, err := message.BoolSelect("Do you want to deploy a test application?")
		if err != nil {
			return fmt.Errorf("failed to select if deploy test application: %w", err)
		}
		if ifDeployTestApplication {
			tfRunnerDriverDefId := session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId
			configDefId := session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId
			err = deployTestApplication(ctx, humanitecPlatform, humanitecClusterId, tfRunnerDriverDefId, configDefId, isAgentInstalled)
			if err != nil {
				return fmt.Errorf("failed to deploy test application: %w", err)
			}
		}

		message.Success("Infrastructure is fully connected!")
		return nil
	},
}

func deployTestApplication(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, humanitecClusterId, humanitecTerraformRunnerId, humanitecConfigId string, createAgentMatchingCriteria bool) error {
	applicationId, err := message.Prompt("Please enter the id for the application you would like to create in your Humanitec Organization", "my-application")
	if err != nil {
		return fmt.Errorf("failed to get application id: %w", err)
	}
	if !utils.IsValidHumanitecId(applicationId) {
		return errors.New("invalid humanitec application id")
	}
	applicationName := applicationId

	err = humanitecPlatform.CreateTestApplication(ctx, applicationId, applicationName)
	if err != nil {
		if errors.Is(err, platform.ErrApplicationAlreadyExists) {
			answer, err := message.BoolSelect("Application already exists. Do you want to continue?")
			if err != nil {
				return fmt.Errorf("failed to select if continue: %w", err)
			}
			if !answer {
				return fmt.Errorf("application already exists")
			}
		} else {
			return fmt.Errorf("failed to create application: %w", err)
		}
	}
	session.State.Application.Connect.HumanitecApplicationId = applicationId
	if err := session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	environmentTypeId := "development"
	environmentId := "development"

	err = humanitecPlatform.CreateEnvTypeAndResIdMatchingCriteria(ctx, environmentTypeId, humanitecClusterId, "")
	if err != nil {
		return fmt.Errorf("failed to create test application matching criteria for definition with id '%s': %w", humanitecClusterId, err)
	}

	err = humanitecPlatform.CreateEnvTypeAndResIdMatchingCriteria(ctx, environmentTypeId, humanitecTerraformRunnerId, "")
	if err != nil {
		return fmt.Errorf("failed to create test application matching criteria for definition with id '%s': %w", humanitecTerraformRunnerId, err)
	}

	err = humanitecPlatform.CreateEnvTypeAndResIdMatchingCriteria(ctx, environmentTypeId, humanitecConfigId, tfRunnerConfigResId)
	if err != nil {
		return fmt.Errorf("failed to create test application matching criteria for definition with id '%s': %w", humanitecConfigId, err)
	}

	if createAgentMatchingCriteria {
		agentId := fmt.Sprintf("agent-%s", humanitecClusterId)
		err = humanitecPlatform.CreateEnvTypeAndResIdMatchingCriteria(ctx, environmentTypeId, agentId, "")
		if err != nil {
			return fmt.Errorf("failed to create test application matching criteria for definition with id '%s': %w", agentId, err)
		}
	}

	pipelineId, pipelineRunId, err := humanitecPlatform.DeployTestApplication(ctx, applicationId, environmentId)
	if err != nil {
		return fmt.Errorf("failed to deploy test application: %w", err)
	}

	pipelineRunUrl := fmt.Sprintf("https://app.humanitec.io/orgs/%s/apps/%s/pipelines/%s/runs/%s", humanitecPlatform.OrganizationId, applicationId, pipelineId, pipelineRunId)

	message.Info("Waiting for pipeline run to complete: %s", pipelineRunUrl)

	err = humanitecPlatform.WaitForPipelineRunComplete(ctx, applicationId, pipelineId, pipelineRunId)
	if err != nil {
		if errors.Is(err, platform.ErrPipelineRunFailed) {
			message.Error("Pipeline failed. Please check the logs in Humanitec: %s", pipelineRunUrl)
		}
		return fmt.Errorf("failed to wait for pipeline complete: %w", err)
	}

	message.Success("Test application deployed successfully")
	return nil
}

func installOperator(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, provider cloud.Provider, kubeconfig, clusterId string) error {
	var operatorNamespace string
	if session.State.Application.Connect.OperatorNamespace != "" {
		operatorNamespace = session.State.Application.Connect.OperatorNamespace
		message.Info("Using operator namespace from previous session: %s", operatorNamespace)
	} else {
		var err error
		operatorNamespace, err = message.Prompt("Please enter the namespace for the operator you would like to create in your Humanitec Organization", "humanitec-operator-system")
		if err != nil {
			return fmt.Errorf("failed to get operator namespace: %w", err)
		}
		session.State.Application.Connect.OperatorNamespace = operatorNamespace
		if err := session.Save(); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}
	}

	shouldInstallOperator := true
	isOperatorInstalled, err := cluster.IsOperatorInstalled(kubeconfig, operatorNamespace)
	if err != nil {
		return fmt.Errorf("failed to check if operator is already installed: %w", err)
	}
	if isOperatorInstalled {
		answer, err := message.BoolSelect("Operator already installed. Do you want to update it?")
		if err != nil {
			return fmt.Errorf("failed to select if update operator: %w", err)
		}
		if !answer {
			message.Info("Operator already installed")
			shouldInstallOperator = false
		}
	}
	if shouldInstallOperator {
		_, err = cluster.InstallUpgradeOperator(kubeconfig, operatorNamespace, nil)
		if err != nil {
			return fmt.Errorf("failed to install operator: %w", err)
		}
	}

	if err = cluster.WaitForReadyDeployment(ctx, kubeconfig, operatorNamespace, "humanitec-operator-controller-manager"); err != nil {
		return fmt.Errorf("operator deployment is not ready: %w", err)
	}

	if err := cluster.ConfigureDriverAuth(ctx, kubeconfig, operatorNamespace, humanitecPlatform); err != nil {
		return fmt.Errorf("failed to configure operator to use drivers: %w", err)
	}

	var humanitecSecretStoreId string
	if session.State.Application.Connect.HumanitecSecretStoreId != "" {
		humanitecSecretStoreId = session.State.Application.Connect.HumanitecSecretStoreId
		message.Info("Using secret store from previous session: %s", humanitecSecretStoreId)
	} else {
		humanitecSecretStoreId, err = message.Prompt("Please enter the id for the secret store you would like to create in your Humanitec Organization", "my-secret-store")
		if err != nil {
			return fmt.Errorf("failed to get cluster name: %w", err)
		}
		session.State.Application.Connect.HumanitecSecretStoreId = humanitecSecretStoreId
		if err := session.Save(); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}
	}

	secretManager, err := selectSecretManager(ctx, provider)
	if err != nil {
		return fmt.Errorf("failed to select secret manager: %w", err)
	}

	err = provider.ConfigureOperator(ctx, humanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId)
	if err != nil {
		return fmt.Errorf("failed to configure operator access: %w", err)
	}
	message.Info("Humanitec Operator installed successfully")
	return nil
}

func connectCluster(ctx context.Context, provider cloud.Provider, clusterId, loadBalancer, cloudAccountId string) (string, error) {
	var humanitecClusterId, humanitecClusterName string
	if session.State.Application.Connect.HumanitecClusterId != "" {
		humanitecClusterId = session.State.Application.Connect.HumanitecClusterId
		humanitecClusterName = humanitecClusterId
		message.Info("Using cluster name from previous session: %s", humanitecClusterId)
	} else {
		var err error
		humanitecClusterId, err = message.Prompt("Please enter the id for the cluster you would like to create in your Humanitec Organization", "my-cluster")
		if err != nil {
			return "", fmt.Errorf("failed to get cluster name: %w", err)
		}
		if !utils.IsValidHumanitecId(humanitecClusterId) {
			return "", errors.New("invalid humanitec cluster id")
		}
		humanitecClusterName = humanitecClusterId
		session.State.Application.Connect.HumanitecClusterId = humanitecClusterId
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save session: %w", err)
		}
	}

	_, err := provider.ConnectCluster(ctx, clusterId, loadBalancer, cloudAccountId, humanitecClusterId, humanitecClusterName)
	if err != nil {
		return "", fmt.Errorf("failed to connect cluster: %w", err)
	}
	message.Success("Cluster connected: %s", clusterId)
	return humanitecClusterId, nil
}

func selectSecretManager(ctx context.Context, provider cloud.Provider) (string, error) {
	if session.State.Application.Connect.CloudSecretManagerId != "" {
		message.Info("Using secret manager from previous session: %s", session.State.Application.Connect.CloudSecretManagerId)
		return session.State.Application.Connect.CloudSecretManagerId, nil
	}

	secretManagers, err := provider.ListSecretManagers(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list secret managers: %w", err)
	}
	if len(secretManagers) == 0 {
		return "", fmt.Errorf("no secret managers found")
	}
	var secretManagerId string
	if len(secretManagers) == 1 {
		secretManagerId = secretManagers[0]
	} else {
		secretManagerId, err = message.Select("Select secret manager", secretManagers)
		if err != nil {
			return "", fmt.Errorf("failed to select secret manager: %w", err)
		}
	}
	session.State.Application.Connect.CloudSecretManagerId = secretManagerId
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save session: %w", err)
	}
	return secretManagerId, nil
}

func installAgent(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, humClusterId, kubeConfigPath string) error {
	message.Info("Installing Humanitec Agent")
	keyPair, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	agentId := fmt.Sprintf("agent-%s", humClusterId)

	message.Info("Creating Humanitec Agent Resource Definition: %s", agentId)
	createResourceResp, err := humanitecPlatform.Client.CreateResourceDefinitionWithResponse(ctx, humanitecPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
		Type:       "agent",
		Name:       agentId,
		Id:         agentId,
		DriverType: "humanitec/agent",
		DriverInputs: &client.ValuesSecretsRefsRequest{
			Values: &map[string]interface{}{
				"id": agentId,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create resource definition: %w", err)
	}
	if createResourceResp.StatusCode() != 200 {
		return fmt.Errorf("humanitec returned unexpected status code: %d with body %s", createResourceResp.StatusCode(), string(createResourceResp.Body))
	}

	message.Info("Creating Humanitec Agent: %s", agentId)
	description := fmt.Sprintf("Agent for cluster %s", humClusterId)
	createAgentResp, err := humanitecPlatform.Client.CreateAgentWithResponse(ctx, humanitecPlatform.OrganizationId, client.CreateAgentJSONRequestBody{
		Description: &description,
		Id:          agentId,
		PublicKey:   string(keyPair.Public),
	})
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	if createAgentResp.StatusCode() != 200 {
		return fmt.Errorf("humanitec returned unexpected status code: %d with body %s", createAgentResp.StatusCode(), string(createAgentResp.Body))
	}

	helmName, err := cluster.InstallAgent(humanitecPlatform.OrganizationId, string(keyPair.Private), kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to install agent: %w", err)
	}

	message.Info("Agent installed successfully: %s", helmName)
	return nil
}

func addAgentToClusterDefinition(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, humClusterId string) error {
	if r, err := humanitecPlatform.Client.GetResourceDefinitionWithResponse(ctx, humanitecPlatform.OrganizationId, humClusterId, &client.GetResourceDefinitionParams{}); err != nil {
		return fmt.Errorf("failed to get cluster resource definition: %w", err)
	} else if r.JSON200 == nil {
		return fmt.Errorf("humanitec returned unexpected status code: %d with body %s", r.StatusCode(), string(r.Body))
	} else if r.JSON200.DriverInputs != nil && r.JSON200.DriverInputs.SecretRefs != nil && (*r.JSON200.DriverInputs.SecretRefs)["agent_url"] != nil {
		return nil
	}

	updateClusterResp, err := humanitecPlatform.Client.PatchResourceDefinitionWithResponse(ctx, humanitecPlatform.OrganizationId, humClusterId, client.PatchResourceDefinitionJSONRequestBody{
		DriverInputs: &client.ValuesSecretsRefsRequest{
			Secrets: &map[string]any{
				"agent_url": "${resources['agent#agent'].outputs.url}",
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update cluster resource definition: %w", err)
	}
	if updateClusterResp.StatusCode() != 200 {
		return fmt.Errorf("humanitec returned unexpected status code: %d with body %s", updateClusterResp.StatusCode(), string(updateClusterResp.Body))
	}
	message.Info("Updated cluster resource definition with agent url")
	return nil
}

func getLoadBalancer(ctx context.Context, provider cloud.Provider, clusterId string) (string, error) {
	if session.State.Application.Connect.CloudLoadBalancerId != "" {
		message.Info("Using load balancer from previous session: %s", session.State.Application.Connect.CloudLoadBalancerId)
		return session.State.Application.Connect.CloudLoadBalancerId, nil
	}

	loadBalancers, err := provider.ListLoadBalancers(ctx, clusterId)
	if err != nil {
		return "", fmt.Errorf("failed to list load balancers: %w", err)
	}
	var loadBalancerId string
	if len(loadBalancers) == 0 {
		answer, err := message.BoolSelect("No load balancers found in the cluster. Do you want to manually specify one?")
		if err != nil {
			return "", fmt.Errorf("failed to select load balancer: %w", err)
		} else if !answer {
			return "", fmt.Errorf("no load balancers found")
		}
		prompt, err := message.Prompt("Please enter the load balancer ip:", "")
		if err != nil {
			return "", fmt.Errorf("failed to select value")
		} else if !utils.IsIpLbAddress(prompt) {
			return "", fmt.Errorf("please provide a valid IPv4 address")
		}
		loadBalancerId = prompt
	} else if len(loadBalancers) == 1 {
		answer, err := message.BoolSelect(fmt.Sprintf("Only one load balancer found: %s. Do you want to use it?", loadBalancers[0]))
		if err != nil {
			return "", fmt.Errorf("failed to select load balancer: %w", err)
		}
		if !answer {
			return "", errors.New("no load balancer selected")
		}
		loadBalancerId = loadBalancers[0]
	} else {
		loadBalancerId, err = message.Select("Select load balancer", loadBalancers)
		if err != nil {
			return "", fmt.Errorf("failed to select load balancer: %w", err)
		}
	}
	session.State.Application.Connect.CloudLoadBalancerId = loadBalancerId
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save session: %w", err)
	}
	return loadBalancerId, nil
}

func getCluster(ctx context.Context, provider cloud.Provider) (string, error) {
	message.DocumentationReference(
		"The Humanitec Platform Orchestrator is designed to integrate with your existing Kubernetes clusters wherever they’re hosted. You can configure the Orchestrator to run your Application in a single Kubernetes cluster or across different clusters in a multi-cloud setup while having an all-in-one solution for managing what is running where.",
		"https://developer.humanitec.com/integration-and-extensions/containerization/kubernetes/",
	)

	if session.State.Application.Connect.CloudClusterId != "" {
		message.Info("Using cluster from previous session: %s", session.State.Application.Connect.CloudClusterId)
		return session.State.Application.Connect.CloudClusterId, nil
	}

	clusters, err := provider.ListClusters(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list clusters: %w", err)
	}
	var clusterId string
	if len(clusters) == 0 {
		return "", fmt.Errorf("no clusters found")
	} else if len(clusters) == 1 {
		answer, err := message.BoolSelect(fmt.Sprintf("Only one cluster found: %s. Do you want to use it", clusters[0]))
		if err != nil {
			return "", fmt.Errorf("failed to select cluster: %w", err)
		}
		if !answer {
			return "", errors.New("no cluster selected")
		}
		clusterId = clusters[0]
	} else {
		clusterId, err = message.Select("Select cluster", clusters)
		if err != nil {
			return "", fmt.Errorf("failed to select cluster: %w", err)
		}
	}
	session.State.Application.Connect.CloudClusterId = clusterId
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save session: %w", err)
	}
	return clusterId, nil
}

func initializeHumanitecPlatformAndSaveSession(ctx context.Context) (*platform.HumanitecPlatform, error) {
	humanitecPlaform, err := initializeHumanitecPlatform(ctx, session.State.Application.Connect.HumanitecOrganizationId)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize humanitec platform: %w", err)
	}
	session.State.Application.Connect.HumanitecOrganizationId = humanitecPlaform.OrganizationId
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}
	return humanitecPlaform, nil
}

func selectCloudProvider(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (cloud.Provider, error) {
	providersFactory := cloud.GetProvidersFactory()

	var providerId string
	if session.State.Application.Connect.CloudProviderId != "" {
		providerId = session.State.Application.Connect.CloudProviderId
		message.Info("Using cloud provider from previous session: %s", providerId)
	} else {
		providersIds := make([]string, len(providersFactory))
		i := 0
		for id := range providersFactory {
			providersIds[i] = id
			i++
		}

		var err error
		providerId, err = message.Select("Select cloud provider", providersIds)
		if err != nil {
			return nil, fmt.Errorf("failed to select cloud provider: %w", err)
		}

		session.State.Application.Connect.CloudProviderId = providerId
		if err := session.Save(); err != nil {
			return nil, fmt.Errorf("failed to save session: %w", err)
		}
	}

	provider, err := providersFactory[providerId](ctx, humanitecPlatform)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud provider: %w", err)
	}

	callingUserId, err := provider.GetCallingUserId(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get calling user id: %w", err)
	}
	message.Info("Logged in to cloud provider as: %s", callingUserId)

	if err = provider.SetupProvider(ctx); err != nil {
		return nil, fmt.Errorf("failed to set up cloud provider: %w", err)
	}
	message.Debug("Provider setup complete")
	return provider, nil
}

func createCloudIdentity(ctx context.Context, provider cloud.Provider, humanitecPlatform *platform.HumanitecPlatform) (string, error) {
	message.DocumentationReference(
		"A Cloud Account allows you to store credentials for cloud infrastructure which the Platform Orchestrator needs to connect to at a central place in your Humanitec Organization. Configured Cloud Accounts can then be referenced in Resource Definitions to connect to cloud resources, removing the need to maintain those credentials for every single Resource Definition.",
		"https://developer.humanitec.com/platform-orchestrator/security/cloud-accounts/overview/",
	)
	var cloudAccountId, cloudAccountName string
	if session.State.Application.Connect.HumanitecCloudAccountId != "" {
		cloudAccountId = session.State.Application.Connect.HumanitecCloudAccountId
		cloudAccountName = cloudAccountId
		message.Info("Using cloud account id from previous session: %s", cloudAccountId)
	} else {
		var err error
		cloudAccountId, err = message.Prompt("Please enter the id for the cloud account you would like to create in your Humanitec Organization", "my-cloud-account")
		if err != nil {
			return "", fmt.Errorf("failed to get cloud account name: %w", err)
		}
		if !utils.IsValidHumanitecId(cloudAccountId) {
			return "", errors.New("invalid humanitec cloud account id")
		}
		cloudAccountName = cloudAccountId
		session.State.Application.Connect.HumanitecCloudAccountId = cloudAccountId
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save session: %w", err)
		}
	}

	cloudIdentity, err := provider.CreateCloudIdentity(ctx, cloudAccountId, cloudAccountName)
	if err != nil {
		return "", err
	}

	result, err := humanitecPlatform.CheckResourceAccountValidity(ctx, cloudIdentity)
	if err != nil {
		return "", fmt.Errorf("failed to check resource account validity: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("resource account validity check failed: %s", *result.Error)
	}
	for _, warning := range result.Warnings {
		message.Warning("Resource account validity check warning: %s", warning)
	}

	message.Success("Cloud account created and successfully validated: %s", cloudIdentity)
	return cloudIdentity, nil
}

func createResourcesForTerraformRunnerExecution(
	ctx context.Context,
	provider cloud.Provider, humPlatform *platform.HumanitecPlatform,
) error {

	clusterId := session.State.Application.Connect.CloudClusterId
	if clusterId == "" {
		return errors.New("clusterId empty in session state, can't proceed")
	}

	kubeConfigPath, err := provider.WriteKubeConfig(ctx, clusterId)
	if err != nil {
		return fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	var tfRunnerNamespace = session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerNamespace
	if tfRunnerNamespace == "" {
		tfRunnerNamespace, err = message.Prompt("Please enter the id of the namespace where the runner will run. The wizard will create it if it does not exist.", "humanitec-terraform")
		if err != nil {
			return fmt.Errorf("failed to get namespace id: %w", err)
		}
	}

	if err := ensureTerraformRunnerNamespace(ctx, kubeConfigPath, tfRunnerNamespace); err != nil {
		return fmt.Errorf("failed to ensure existence of the namespace '%s': %w", tfRunnerNamespace, err)
	}

	var tfRunnerServiceAccountName = session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sServiceAccount
	if tfRunnerServiceAccountName == "" {
		tfRunnerServiceAccountName, err = message.Prompt("Please enter the name of the k8s service account the wizard will create to let the runner run with", "humanitec-tf-runner")
		if err != nil {
			return fmt.Errorf("failed to get service account name: %w", err)
		}
	}

	if err := ensureTerraformServiceAccount(ctx, kubeConfigPath, tfRunnerServiceAccountName, tfRunnerNamespace); err != nil {
		return fmt.Errorf("failed to ensure existence of the service account '%s': %w", tfRunnerServiceAccountName, err)
	}

	var configRunnerResourceDefId = session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId
	if configRunnerResourceDefId == "" {
		configRunnerResourceDefId, err = message.Prompt("Please enter the id of the config resource definition that will be created to inject Terraform runner credentials", "my-tf-runner-config")
		if err != nil {
			return fmt.Errorf("failed to get config runner definition id: %w", err)
		}
	}

	agentInstalled, err := cluster.IsAgentInstalled(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to check if cluster is humanitec agent installed in the cluster: %w", err)
	}

	if err := ensureConfigRunnerResourceDefinition(ctx, humPlatform, configRunnerResourceDefId, agentInstalled); err != nil {
		return fmt.Errorf("failed to ensure existence of the config runner resource definition id '%s': %w", configRunnerResourceDefId, err)
	}

	var tfRunnerDriverDefId = session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId
	if tfRunnerDriverDefId == "" {
		tfRunnerDriverDefId, err = message.Prompt("Please enter the id of the terraform-runner driver resource definition that will be created to provision a fake s3 bucket", "my-vd-tf-fake-s3")
		if err != nil {
			return fmt.Errorf("failed to get application id: %w", err)
		}
	}
	if err := ensureTFRunnerDriverResourceDefinition(ctx, humPlatform, tfRunnerDriverDefId); err != nil {
		return fmt.Errorf("failed to ensure existence of s3 resource definition id '%s': %w", tfRunnerDriverDefId, err)
	}

	return nil
}

func ensureTerraformRunnerNamespace(ctx context.Context, kubeConfigPath, namespaceName string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)

	if err != nil {
		return fmt.Errorf("failed to read kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create a client from kubeconfig: %w", err)
	}

	message.Info("Creating namespace '%s' where the Terraform Runner should run", namespaceName)
	if _, err = clientset.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}, metav1.CreateOptions{}); err != nil {
		var sErr *kerrors.StatusError
		if errors.As(err, &sErr) && sErr.ErrStatus.Code == 409 {
			message.Info("Namespace '%s' already exists", namespaceName)
		} else {
			return fmt.Errorf("failed to create namespace '%s': %w", namespaceName, err)
		}
	} else {
		message.Info("Namespace '%s' created", namespaceName)
	}

	session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerNamespace = namespaceName
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	return nil
}

func ensureTerraformServiceAccount(ctx context.Context, kubeConfigPath, serviceAccountName, namespace string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create a client from kubeconfig: %w", err)
	}

	message.Info("Creating k8s service account '%s' the Terraform Runner should run with", serviceAccountName)
	if _, err = clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		var sErr *kerrors.StatusError
		if errors.As(err, &sErr) && sErr.ErrStatus.Code == 409 {
			message.Info("k8s service account '%s' already exists", serviceAccountName)
		} else {
			return fmt.Errorf("failed to create k8s service account '%s': %w", serviceAccountName, err)
		}
	} else {
		message.Info("k8s service account '%s' created", serviceAccountName)
	}

	session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sServiceAccount = serviceAccountName
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	message.Info("Creating the k8s role '%s' to bind to the Service Account", serviceAccountName)
	if _, err = clientset.RbacV1().Roles(namespace).Create(ctx, &k8s_rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
		Rules: []k8s_rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "get", "delete", "list", "update", "deletecollection"},
			},
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"create", "get", "list", "update", "watch"},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		var sErr *kerrors.StatusError
		if errors.As(err, &sErr) && sErr.ErrStatus.Code == 409 {
			message.Info("K8s role '%s' already exists", serviceAccountName)
		} else {
			return fmt.Errorf("failed to create k8s role '%s': %w", serviceAccountName, err)
		}
	} else {
		message.Info("K8s role '%s' created", serviceAccountName)

	}

	message.Info("Binding the k8s role '%s' to the runner service account", serviceAccountName)
	if _, err = clientset.RbacV1().RoleBindings(namespace).Create(ctx, &k8s_rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
		RoleRef: k8s_rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     serviceAccountName,
		},
		Subjects: []k8s_rbac.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: namespace,
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		var sErr *kerrors.StatusError
		if errors.As(err, &sErr) && sErr.ErrStatus.Code == 409 {
			message.Info("K8s role binding '%s' already exists", serviceAccountName)
		} else {
			return fmt.Errorf("failed to create k8s role binding '%s': %w", serviceAccountName, err)
		}
	} else {
		message.Info("K8s role binding '%s' created", serviceAccountName)

	}

	session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sRole = serviceAccountName
	if err = session.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func ensureConfigRunnerResourceDefinition(ctx context.Context, humPlatform *platform.HumanitecPlatform, defId string, agentInstalled bool) error {
	clusterDefId := session.State.Application.Connect.HumanitecClusterId
	if clusterDefId == "" {
		return errors.New("humanitec cluster definition id empty in session state, can't proceed")
	}
	clusterResp, err := humPlatform.Client.GetResourceDefinitionWithResponse(ctx, humPlatform.OrganizationId, clusterDefId, &client.GetResourceDefinitionParams{})
	if err != nil {
		return fmt.Errorf("failed to retrieve cluster definition with id '%s': %w", clusterDefId, err)
	}
	if clusterResp.StatusCode() != http.StatusOK {
		return fmt.Errorf("humanitec returned unexpected status code %d with body %s while fetching cluster definition with id '%s'", clusterResp.StatusCode(), string(clusterResp.Body), clusterDefId)
	}

	clusterDef := *clusterResp.JSON200
	var accountId = fmt.Sprintf("%s/%s", humPlatform.OrganizationId, session.State.Application.Connect.HumanitecCloudAccountId)
	if clusterDef.DriverAccount != nil {
		accountId = fmt.Sprintf("%s/%s", humPlatform.OrganizationId, *clusterDef.DriverAccount)
	}
	clusterType, ok := clusterTypeDriverMap[clusterDef.DriverType]
	if !ok {
		return fmt.Errorf("failed to map driver type '%s' to a valid cluster type, valid values for driver type are %v", clusterDef.DriverType, maps.Keys(clusterTypeDriverMap))
	}

	outputs := map[string]interface{}{
		"runner": map[string]interface{}{
			"cluster":         clusterDef.DriverInputs.Values,
			"cluster_type":    clusterType,
			"service_account": session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerK8sServiceAccount,
			"namespace":       session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerNamespace,
			"account":         accountId,
		},
	}
	outputsForTemplates, err := yaml.Marshal(outputs)
	if err != nil {
		return fmt.Errorf("failed to convert outputs map into a yaml string")
	}

	secretsTpl := map[string]interface{}{
		"agent_url": "",
	}
	secrets := map[string]interface{}{}
	if agentInstalled {
		var agentUrl = "${resources.agent.outputs.url}"
		if clusterDef.DriverInputs.SecretRefs != nil {
			if agentUrlSecretRef, ok := (*clusterDef.DriverInputs.SecretRefs)["agent_url"]; ok {
				if agentUrlMap, ok := agentUrlSecretRef.(map[string]interface{}); ok {
					agentUrl = agentUrlMap["value"].(string)
				}
			}
		}
		secrets["agent_url"] = agentUrl
		secretsTpl["agent_url"] = "{{ .driver.secrets.agent_url }}"
	}
	var secretsForTemplates []byte
	if len(secretsTpl) > 0 {
		secretsForTemplates, err = yaml.Marshal(secretsTpl)
		if err != nil {
			return fmt.Errorf("failed to convert outputs map into a yaml string")
		}
	}

	configCreateResp, err := humPlatform.Client.CreateResourceDefinitionWithResponse(ctx, humPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
		Id:         defId,
		DriverType: "humanitec/template",
		DriverInputs: &client.ValuesSecretsRefsRequest{
			Values: &map[string]interface{}{
				"templates": map[string]interface{}{
					"outputs": "\n" + string(outputsForTemplates),
					"secrets": "\n" + string(secretsForTemplates),
				},
			},
			Secrets: &secrets,
		},
		Type: "config",
	})
	if err != nil {
		return fmt.Errorf("failed to create config runner definition with id '%s': %w", defId, err)
	}
	switch configCreateResp.StatusCode() {
	case http.StatusOK:
		message.Info("Config runner resource definition with id '%s' created", defId)
		session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId = defId
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	case http.StatusConflict:
		message.Info("Resource definition with id '%s' already exists", defId)
		if session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId == defId {
			return nil
		}
		configGetResp, err := humPlatform.Client.GetResourceDefinitionWithResponse(ctx, humPlatform.OrganizationId, defId, &client.GetResourceDefinitionParams{})
		if err != nil {
			return fmt.Errorf("failed to retrieve resource definition with id '%s': %w", defId, err)
		}
		if configGetResp.StatusCode() != http.StatusOK {
			return fmt.Errorf("humanitec returned unexpected status code %d with body %s while fetching resource definition with id '%s'", configGetResp.StatusCode(), string(configGetResp.Body), defId)
		}

		if b, err := message.BoolSelect(fmt.Sprintf("A resource definition with id '%s' already exists. Do you want to use it in this wizard run?", defId)); err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		} else {
			if b {
				session.State.Application.Connect.TerraformRunnerResouces.ConfigRunnerResourceDefinitionId = defId
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				return fmt.Errorf("resource definition with id '%s' already exists. Please delete it or choose another id for the config runner definition before proceeding with the wizard run", defId)
			}
		}
	default:
		return fmt.Errorf("humanitec returned unexpected status code %d with body %s while creating config resource definition with id '%s'", configCreateResp.StatusCode(), string(configCreateResp.Body), defId)
	}
	return nil
}

func ensureTFRunnerDriverResourceDefinition(ctx context.Context, humPlatform *platform.HumanitecPlatform, defId string) error {
	s3CreateResp, err := humPlatform.Client.CreateResourceDefinitionWithResponse(ctx, humPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
		Type:       "s3",
		DriverType: "humanitec/terraform-runner",
		Id:         defId,
		DriverInputs: &client.ValuesSecretsRefsRequest{
			Values: &map[string]interface{}{
				"files": map[string]interface{}{
					"main.tf": `
resource "random_id" "thing" {
	byte_length = 8
}

output "bucket" {
	value = random_id.thing.hex
}
`,
				},
				"append_logs_to_error": true,
			},
		},
	},
	)
	if err != nil {
		return fmt.Errorf("failed to create s3 definition with id '%s': %w", defId, err)
	}

	switch s3CreateResp.StatusCode() {
	case http.StatusOK:
		message.Info("S3 resource definition with id '%s' created", defId)
		session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId = defId
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	case http.StatusConflict:
		message.Info("Resource definition with id '%s' already exists", defId)
		if session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId == defId {
			return nil
		}
		s3GetResp, err := humPlatform.Client.GetResourceDefinitionWithResponse(ctx, humPlatform.OrganizationId, defId, &client.GetResourceDefinitionParams{})
		if err != nil {
			return fmt.Errorf("failed to retrieve resource definition with id '%s': %w", defId, err)
		}
		if s3GetResp.StatusCode() != http.StatusOK {
			return fmt.Errorf("humanitec returned unexpected status code %d with body %s while fetching resource definition with id '%s'", s3GetResp.StatusCode(), string(s3GetResp.Body), defId)
		}

		if b, err := message.BoolSelect(fmt.Sprintf("A resource definition with id '%s' already exists. Do you want to use it in this wizard run?", defId)); err != nil {
			return fmt.Errorf("failed to get user input: %w", err)
		} else {
			if b {
				session.State.Application.Connect.TerraformRunnerResouces.TerraformRunnerDriverResourceDefinitionId = defId
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				return fmt.Errorf("resource definition with id '%s' already exists. Please delete it or choose another id for the config res-id-util definition before proceeding with the wizard run", defId)
			}
		}
	default:
		return fmt.Errorf("humanitec returned unexpected status code %d with body %s while creating s3 resource definition with id '%s'", s3CreateResp.StatusCode(), string(s3CreateResp.Body), defId)
	}
	return nil

}

func init() {
	rootCmd.AddCommand(connectCmd)
}
