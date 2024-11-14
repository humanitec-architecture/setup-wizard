package cmd

import (
	"fmt"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/respack"
	"github.com/spf13/cobra"
)

const (
	resourcesPrefix = "setup-wizard-"
	envType         = "development"
)

var installResourcePackCmd = &cobra.Command{
	Use:   "install-resource-pack",
	Short: "Register an in-cluster resource pack on the Humanitec platform",
	Long: `It will guide you through the process of registering an in-cluster resource pack on the Humanitec platform.
More info about the resource packs can be found at https://developer.humanitec.com/platform-orchestrator/resources/resource-packs/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		humanitecPlatform, err := initializeHumanitecPlatform(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to initialize humanitec platform: %w", err)
		}

		message.Info("Downloading resource pack")
		pack, err := respack.Download(ctx, respack.InCluster)
		if err != nil {
			return fmt.Errorf("failed to download resource pack: %w", err)
		}

		for _, resource := range pack.Resources {
			resDefId := resourcesPrefix + resource.Name

			resDefs, err := humanitecPlatform.SelectResourceDefinitions(ctx,
				platform.AllSelectResourceDefinitionsCriteria(
					isNot(resDefId),
					isResourceType(resource.Type),
					matchToEnvType(envType),
				),
			)
			if err != nil {
				return fmt.Errorf("error fetching resource definitions: %w", err)
			}
			if len(resDefs) > 0 {
				message.Info("Resource of type: '%s' already exists, skipping installation of: '%s'", resource.Type, resource.Name)
				continue
			}

			message.Info("Registering resource: '%s'", resDefId)
			err = humanitecPlatform.ApplyTerraform(ctx, resource.Path, map[string]string{
				"prefix": resourcesPrefix,
			})
			if err != nil {
				return fmt.Errorf("failed to register resource: '%s' with Terraform: %w", resource.Name, err)
			}

			message.Info("Creating matching criteria for resource: '%s'", resDefId)
			err = humanitecPlatform.CreateEnvTypeAndResIdMatchingCriteria(ctx, envType, resDefId, "")
			if err != nil {
				return fmt.Errorf("failed to create matching criteria for resource: '%s': %w", resDefId, err)
			}
		}

		message.Success("Resource pack registered successfully")
		return nil
	},
}

func isResourceType(resType string) func(resDef client.ResourceDefinitionResponse) bool {
	return func(resDef client.ResourceDefinitionResponse) bool {
		return resDef.Type == resType
	}
}

func matchToEnvType(envType string) func(resDef client.ResourceDefinitionResponse) bool {
	return func(resDef client.ResourceDefinitionResponse) bool {
		if resDef.Criteria != nil {
			for _, criteria := range *resDef.Criteria {
				if criteria.EnvType != nil && *criteria.EnvType == envType && criteria.AppId == nil && criteria.EnvId == nil && criteria.ResId == nil && criteria.Class == "default" {
					return true
				}
			}
		}
		return false
	}
}

func isNot(resDefId string) func(resDef client.ResourceDefinitionResponse) bool {
	return func(resDef client.ResourceDefinitionResponse) bool {
		return resDef.Id != resDefId
	}
}

func init() {
	rootCmd.AddCommand(installResourcePackCmd)
}
