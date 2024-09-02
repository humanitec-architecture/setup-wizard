package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
)

var ErrEnvironmentTypeAlreadyExists = fmt.Errorf("environment type already exists")

func (p *HumanitecPlatform) CreateTestEnvironmentType(ctx context.Context, environmentTypeId string) error {
	getEnvironmentTypeResp, err := p.Client.GetEnvironmentTypeWithResponse(ctx, p.OrganizationId, environmentTypeId)
	if err != nil {
		return fmt.Errorf("failed to get environment type: %w", err)
	}
	if getEnvironmentTypeResp.StatusCode() == http.StatusOK {
		return ErrEnvironmentTypeAlreadyExists
	}
	if getEnvironmentTypeResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", getEnvironmentTypeResp.StatusCode(), string(getEnvironmentTypeResp.Body))
	}

	createEnvironmentTypeResp, err := p.Client.CreateEnvironmentTypeWithResponse(ctx, p.OrganizationId, client.EnvironmentTypeRequest{
		Id: environmentTypeId,
	})
	if err != nil {
		return fmt.Errorf("failed to create environment type: %w", err)
	}
	if createEnvironmentTypeResp.StatusCode() != 201 {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", createEnvironmentTypeResp.StatusCode(), string(createEnvironmentTypeResp.Body))
	}
	return nil
}
