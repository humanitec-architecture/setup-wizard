package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
)

var ErrApplicationAlreadyExists = fmt.Errorf("application already exists")

func (p *HumanitecPlatform) CreateTestApplication(ctx context.Context, applicationId, applicationName string) error {
	getApplicationResp, err := p.Client.GetApplicationWithResponse(ctx, p.OrganizationId, applicationId)
	if err != nil {
		return fmt.Errorf("failed to get application: %w", err)
	}
	if getApplicationResp.StatusCode() == http.StatusOK {
		return ErrApplicationAlreadyExists
	}
	if getApplicationResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", getApplicationResp.StatusCode(), string(getApplicationResp.Body))
	}

	createApplicationResp, err := p.Client.CreateApplicationWithResponse(ctx, p.OrganizationId, client.ApplicationCreationRequest{
		Id:   applicationId,
		Name: applicationName,
	})
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	if createApplicationResp.StatusCode() != 201 {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", createApplicationResp.StatusCode(), string(createApplicationResp.Body))
	}
	return nil
}
