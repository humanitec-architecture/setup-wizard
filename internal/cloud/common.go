package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/humanitec/humanitec-go-autogen"
	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/utils"
)

func SaveState(filename string, state interface{}) error {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	stateFile, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(path.Join(dirname, filename), stateFile, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

func LoadState(filename string) ([]byte, error) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	stateFile, err := os.ReadFile(path.Join(dirname, filename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	} else {
		return stateFile, nil
	}
}

func CheckResourceAccount(ctx context.Context, client *humanitec.Client, orgID, cloudAccountID string) error {
	resp, err := client.CheckResourceAccountWithResponse(ctx, orgID, cloudAccountID)
	if err != nil {
		return fmt.Errorf("failed to check Cloud Account '%s' with Humanitec: %w", cloudAccountID, err)
	}

	if resp.StatusCode() == http.StatusOK {
		if resp.JSON200.Warnings != nil {
			message.Info("check Cloud Account '%s' received some warnings: %v", cloudAccountID, *resp.JSON200.Warnings)
		}
		return nil
	}

	if resp.StatusCode() == http.StatusBadRequest {
		return fmt.Errorf("check Cloud Account '%s' with Humanitec unsuccessful. %s %s %v", cloudAccountID, resp.JSON400.Error, resp.JSON400.Message, resp.JSON400.Details)
	}
	return fmt.Errorf("failed to check Cloud Account '%s' with Humanitec: unexpected status code %d", cloudAccountID, resp.StatusCode())
}

func CreateResourceAccount(ctx context.Context, humClient *humanitec.Client, orgID string, req client.CreateResourceAccountRequestRequest) error {
	resp, err := humClient.CreateResourceAccountWithResponse(ctx, orgID,
		&client.CreateResourceAccountParams{
			CheckCredential: utils.Ref(true),
		}, req)
	if err != nil {
		return fmt.Errorf("failed to create Cloud Account '%s' in Humanitec: %w", req.Id, err)
	}
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusBadRequest {
		return fmt.Errorf("failed to create or test Cloud Account '%s' in Humanitec. Code: %s - message: %s - details: %v", req.Id, resp.JSON400.Error, resp.JSON400.Message, resp.JSON400.Details)
	}
	return fmt.Errorf("failed to create Cloud Account '%s' in Humanitec: unexpected status code %d instead of %d", req.Id, resp.StatusCode(), http.StatusOK)
}

func createResourceAccountWithRetries(ctx context.Context, client *humanitec.Client, orgID string, req client.CreateResourceAccountRequestRequest, timeout time.Duration) error {
	timeoutAfter := time.After(timeout)
	ticker := time.NewTicker(5 * time.Second)
	tick := ticker.C
	defer ticker.Stop()
	
	var err error
	for loop := true; loop; {
		select {
		case <-timeoutAfter:
			return fmt.Errorf("error creating resource account (retry timeout exceeded), %w", err)
		case <-tick:
			if err = CreateResourceAccount(ctx, client, orgID, req); err != nil {
				message.Debug("error creating resource account, retrying: %v", err)
				continue
			}
			loop = false
		}
	}
	return nil
}
