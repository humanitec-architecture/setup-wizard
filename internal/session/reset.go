package session

import (
	"fmt"
	"os"
	"path"
)

func Reset() error {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	dirname = path.Join(dirname, stateFileDirectory)

	if err = os.RemoveAll(path.Join(dirname, stateFileName)); err != nil {
		return fmt.Errorf("failed to remove state file: %w", err)
	}
	return nil
}
