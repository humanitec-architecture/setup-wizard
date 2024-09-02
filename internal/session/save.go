package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
)

func Save() error {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	dirname = path.Join(dirname, stateFileDirectory)

	err = os.MkdirAll(dirname, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create state file directory: %w", err)
	}

	stateFile, err := json.Marshal(State)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(path.Join(dirname, stateFileName), stateFile, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}
