package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/humanitec/humctl-wizard/internal/message"
)

var ErrStateFileNotFound = errors.New("state file not found")

func Load(force bool) error {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	dirname = path.Join(dirname, stateFileDirectory)

	stateFile, err := os.ReadFile(path.Join(dirname, stateFileName))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return ErrStateFileNotFound
		}
		message.Debug("State file not found, creating new state")
	} else {
		answer := true
		if !force {
			answer, err = message.BoolSelect("Do you want to load the state from the previous session?")
			if err != nil {
				return fmt.Errorf("failed to get user input: %w", err)
			}
		}
		if answer {
			if err := json.Unmarshal(stateFile, &State); err != nil {
				return fmt.Errorf("failed to unmarshal state file: %w", err)
			}
		}
	}
	return nil
}
