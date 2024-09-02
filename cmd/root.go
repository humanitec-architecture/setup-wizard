package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/session"
)

var silentMode bool
var verboseMode bool
var noEmoji bool
var noColor bool

var rootCmd = &cobra.Command{
	Use:           "github.com/humanitec/humctl-wizard",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		message.SetSilentMode(silentMode)
		message.SetVerboseMode(verboseMode)
		message.SetEmojiMode(!noEmoji)
		message.SetColorMode(!noColor)

		err := session.Load()
		if err != nil {
			return fmt.Errorf("failed to load session: %v", err)
		}
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		message.Error("failed to execute command: %v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&silentMode, "silent", false, "silent mode (hides everything except prompt/failure messages)")
	rootCmd.PersistentFlags().BoolVar(&verboseMode, "verbose", false, "verbose output (show everything, overrides silent mode)")
	rootCmd.PersistentFlags().BoolVar(&noEmoji, "no-emoji", false, "disable emojis")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colors and emojis")
}
