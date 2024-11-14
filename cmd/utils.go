package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"gopkg.in/yaml.v2"
)

func initializeHumanitecPlatform(ctx context.Context, orgId string) (*platform.HumanitecPlatform, error) {
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
		message.Debug("Using Humanitec Token from config file")
	}

	platform, err := platform.NewHumanitecPlatform(humanitecToken)
	if err != nil {
		return nil, err
	}

	if orgId == "" {
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
			orgId = organizations[0].Id
			message.Debug("Only one organization found. Using: %s", platform.OrganizationId)
		} else {
			ids := make([]string, len(organizations))
			for i, org := range organizations {
				ids[i] = org.Id
			}
			orgId, err = message.Select("Select organization", ids)
			if err != nil {
				return nil, err
			}
		}
	}

	platform.OrganizationId = orgId
	return platform, nil
}
