package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
)

var ErrEnvironmentAlreadyExists = fmt.Errorf("environment already exists")

func (p *HumanitecPlatform) CreateTestEnvironment(ctx context.Context, applicationId, environmentId, environmentName, environmentType string) error {
	getEnvironmentResp, err := p.Client.GetEnvironmentWithResponse(ctx, p.OrganizationId, applicationId, environmentId)
	if err != nil {
		return fmt.Errorf("failed to get environment: %w", err)
	}
	if getEnvironmentResp.StatusCode() == http.StatusOK {
		return ErrEnvironmentAlreadyExists
	}
	if getEnvironmentResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", getEnvironmentResp.StatusCode(), string(getEnvironmentResp.Body))
	}

	createEnvironmentResp, err := p.Client.CreateEnvironmentWithResponse(ctx, p.OrganizationId, applicationId, client.EnvironmentDefinitionRequest{
		Id:   environmentId,
		Name: environmentName,
		Type: &environmentType,
	})
	if err != nil {
		return fmt.Errorf("failed to create environment: %w", err)
	}
	if createEnvironmentResp.StatusCode() != 201 {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", createEnvironmentResp.StatusCode(), string(createEnvironmentResp.Body))
	}
	return nil
}
