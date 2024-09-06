package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/cloud"
	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/keys"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/humanitec/humctl-wizard/internal/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect humanitec to an existing cloud resources",
	Long:  `It will guide you through the process of connecting an existing cloud resources to Humanitec.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		humanitecPlatform, err := initializeHumanitecPlatform(ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize humanitec platform: %w", err)
		}

		provider, err := selectCloudProvider(ctx, humanitecPlatform)
		if err != nil {
			return fmt.Errorf("failed to select cloud provider: %w", err)
		}

		cloudAccountId, err := createCloudIdentity(ctx, provider)
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
			}
		} else {
			message.Info("Humanitec Agent already installed")
		}

		isOperatorInstalled, err := provider.IsOperatorInstalled(ctx)
		if err != nil {
			return fmt.Errorf("failed to check if operator is already installed: %w", err)
		}
		if !isOperatorInstalled {
			internalSecrets, err := humanitecPlatform.CheckInternalSecrets(ctx)
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

			if err != nil {
				return fmt.Errorf("failed to check if resource definitions or shared secrets contain internal values: %w", err)
			}

			err = installOperator(ctx, humanitecPlatform, provider, kubeConfigPath, clusterId)
			if err != nil {
				return fmt.Errorf("failed to install operator: %w", err)
			}
			message.Info("Humanitec Operator installed")
		} else {
			message.Info("Humanitec Operator already installed")
		}

		ifDeployTestApplication, err := message.BoolSelect("Do you want to deploy a test application?")
		if err != nil {
			return fmt.Errorf("failed to select if deploy test application: %w", err)
		}
		if ifDeployTestApplication {
			err = deployTestApplication(ctx, humanitecPlatform, humanitecClusterId, isAgentInstalled)
			if err != nil {
				return fmt.Errorf("failed to deploy test application: %w", err)
			}
		}

		message.Success("Infrastructure is fully connected!")
		return nil
	},
}

func deployTestApplication(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, humanitecClusterId string, createAgentMatchingCriteria bool) error {
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

	environmentTypeId := "development"
	environmentId := "development"

	err = humanitecPlatform.CreateEnvTypeMatchingCriteria(ctx, environmentTypeId, humanitecClusterId)
	if err != nil {
		return fmt.Errorf("failed to create test application matching criteria: %w", err)
	}

	if createAgentMatchingCriteria {
		agentId := fmt.Sprintf("agent-%s", humanitecClusterId)
		err = humanitecPlatform.CreateEnvTypeMatchingCriteria(ctx, environmentTypeId, agentId)
		if err != nil {
			return fmt.Errorf("failed to create test application matching criteria: %w", err)
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

	message.Info("Test application deployed successfully")
	return nil
}

func installOperator(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, provider cloud.Provider, kubeconfig, clusterId string) error {
	secretManager, err := selectSecretManager(provider)
	if err != nil {
		return fmt.Errorf("failed to select secret manager: %w", err)
	}

	var operatorNamespace string
	if session.State.Application.Connect.OperatorNamespace != "" {
		operatorNamespace = session.State.Application.Connect.OperatorNamespace
		message.Info("Using operator namespace from previous session: %s", operatorNamespace)
	} else {
		operatorNamespace, err = message.Prompt("Please enter the namespace for the operator you would like to create in your Humanitec Organization", "humanitec-operator-system")
		if err != nil {
			return fmt.Errorf("failed to get operator namespace: %w", err)
		}
		session.State.Application.Connect.OperatorNamespace = operatorNamespace
		if err := session.Save(); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}
	}

	_, err = cluster.InstallOperator(humanitecPlatform.OrganizationId, kubeconfig, operatorNamespace)
	if err != nil {
		return fmt.Errorf("failed to install operator: %w", err)
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
	message.Info("Cluster connected: %s", clusterId)
	return humanitecClusterId, nil
}

func selectSecretManager(provider cloud.Provider) (string, error) {
	if session.State.Application.Connect.CloudSecretManagerId != "" {
		message.Info("Using secret manager from previous session: %s", session.State.Application.Connect.CloudSecretManagerId)
		return session.State.Application.Connect.CloudSecretManagerId, nil
	}

	secretManagers, err := provider.ListSecretManagers()
	if err != nil {
		return "", fmt.Errorf("failed to list secret managers: %w", err)
	}
	if len(secretManagers) == 0 {
		return "", fmt.Errorf("no secret managers found")
	}
	var secretManagerId string
	if len(secretManagers) == 1 {
		answer, err := message.BoolSelect(fmt.Sprintf("Only one secret manager found: %s. Do you want to use it", secretManagers[0]))
		if err != nil {
			return "", fmt.Errorf("failed to select secret manager: %w", err)
		}
		if !answer {
			return "", errors.New("no secret manager selected")
		}
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
	keyPair, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	agentId := fmt.Sprintf("agent-%s", humClusterId)

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

	message.Info("Agent installed successfully: %s", helmName)
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
		return "", fmt.Errorf("no load balancers found")
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

func initializeHumanitecPlatform(ctx context.Context) (*platform.HumanitecPlatform, error) {
	var humanitecToken string

	dirname, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	configFile, err := os.ReadFile(path.Join(dirname, ".humctl"))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		var config struct {
			HumanitecToken string `yaml:"token"`
		}
		if err := yaml.Unmarshal(configFile, &config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
		}
		humanitecToken = config.HumanitecToken
	}

	if humanitecToken == "" {
		humanitecToken, err = message.Prompt("Enter your Humanitec Token", "")
		if err != nil {
			return nil, err
		}
	} else {
		message.Info("Using Humanitec Token from config file")
	}

	platform, err := platform.NewHumanitecPlatform(humanitecToken)
	if err != nil {
		return nil, err
	}

	var organizationId string
	if session.State.Application.Connect.HumanitecOrganizationId != "" {
		organizationId = session.State.Application.Connect.HumanitecOrganizationId
		message.Info("Using organization from previous session: %s", organizationId)
	} else {
		organizationsResp, err := platform.Client.ListOrganizationsWithResponse(ctx)
		if err != nil {
			return nil, err
		}
		if organizationsResp.StatusCode() != 200 {
			return nil, fmt.Errorf("humanitec returned unexpected status code: %d with body %s", organizationsResp.StatusCode(), string(organizationsResp.Body))
		}

		organizations := *organizationsResp.JSON200
		if len(organizations) == 0 {
			return nil, fmt.Errorf("no organizations found")
		}
		if len(organizations) == 1 {
			organizationId = organizations[0].Id
			message.Debug("Only one organization found. Using: %s", platform.OrganizationId)
		} else {
			ids := make([]string, len(organizations))
			for i, org := range organizations {
				ids[i] = org.Id
			}
			organizationId, err = message.Select("Select organization", ids)
			if err != nil {
				return nil, err
			}
		}
	}
	platform.OrganizationId = organizationId
	session.State.Application.Connect.HumanitecOrganizationId = organizationId
	if err := session.Save(); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}
	return platform, nil
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
	return provider, nil
}

func createCloudIdentity(ctx context.Context, provider cloud.Provider) (string, error) {
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
	message.Info("Cloud identity created and successfully tested: %s", cloudIdentity)
	return cloudAccountId, nil
}

func init() {
	rootCmd.AddCommand(connectCmd)
}
