package cmd

import (
	"context"
	"fmt"

	"github.com/humanitec/humctl-wizard/internal/message"

	"github.com/humanitec/humctl-wizard/internal/cloud"
	"github.com/humanitec/humctl-wizard/internal/platform"
)

// var cleanCmd = &cobra.Command{
// 	Use:   "clean",
// 	Short: "Clean resources created by the wizard",
// 	Long:  `It cleans Cloud and Humanitec resources created by the wizard and stored in the state.`,
// 	RunE: func(cmd *cobra.Command, args []string) error {
// 		ctx := cmd.Context()

// 		err := session.Load(true)
// 		if err != nil {
// 			return fmt.Errorf("failed to load session: %v", err)
// 		}

// 		humanitecPlatform, err := initializeHumanitecPlatform(ctx)
// 		if err != nil {
// 			return fmt.Errorf("failed to initialize humanitec platform: %w", err)
// 		}

// 		var provider cloud.Provider
// 		providersFactory := cloud.GetProvidersFactory()
// 		if session.State.Application.Connect.CloudProviderId != "" {
// 			provider, err = providersFactory[session.State.Application.Connect.CloudProviderId](ctx, humanitecPlatform)
// 			if err != nil {
// 				return fmt.Errorf("failed to create cloud provider: %w", err)
// 			}
// 		}

// 		if err := Clean(ctx, humanitecPlatform, provider); err != nil {
// 			return err
// 		}
// 		return nil
// 	},
// }

func init() {
	// rootCmd.AddCommand(cleanCmd)
}

func Clean(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform, provider cloud.Provider) error {
	if provider != nil {
		if err := provider.CleanState(ctx); err != nil {
			return fmt.Errorf("failed to clean resources: %w", err)
		}
	}
	// TODO: clean provider-agnostic stuff (operator, agent)
	message.Success("All resources are removed")
	return nil
}
