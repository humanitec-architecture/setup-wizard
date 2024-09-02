package cmd

import (
	"github.com/spf13/cobra"
)

var constructCmd = &cobra.Command{
	Use:   "construct",
	Short: "Construct new dynamic humanitec cloud resources",
	Long:  `It will guide you through the process of constructing new dynamic humanitec cloud resources.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	rootCmd.AddCommand(constructCmd)
}
