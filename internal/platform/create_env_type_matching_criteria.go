package platform

import (
	"context"
	"fmt"

	"github.com/humanitec/humanitec-go-autogen/client"
)

func (p *HumanitecPlatform) CreateEnvTypeMatchingCriteria(ctx context.Context, environmentTypeId, resourceId string) error {
	createMatchingCriteriaResp, err := p.Client.CreateResourceDefinitionCriteriaWithResponse(ctx, p.OrganizationId, resourceId, client.MatchingCriteriaRuleRequest{
		EnvType: &environmentTypeId,
	})
	if err != nil {
		return fmt.Errorf("failed to create matching criteria: %w", err)
	}
	if createMatchingCriteriaResp.StatusCode() == 409 {
		return nil
	}
	if createMatchingCriteriaResp.StatusCode() != 200 {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", createMatchingCriteriaResp.StatusCode(), string(createMatchingCriteriaResp.Body))
	}

	return nil
}
