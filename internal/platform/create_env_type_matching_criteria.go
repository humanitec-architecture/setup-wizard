package platform

import (
	"context"
	"fmt"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
)

func (p *HumanitecPlatform) CreateEnvTypeAndResIdMatchingCriteria(ctx context.Context, environmentTypeId, defId, resId string) error {
	resDef, err := p.Client.GetResourceDefinitionWithResponse(ctx, p.OrganizationId, defId, nil)
	if err != nil {
		return fmt.Errorf("error fetching resource definition: %w", err)
	}
	if resDef.JSON200 == nil {
		return fmt.Errorf("error fetching resource definition, status code %s: %v", resDef.Status(), string(resDef.Body))
	}
	if resDef.JSON200.Criteria != nil {
		for _, criteria := range *resDef.JSON200.Criteria {
			if criteria.EnvType != nil && *criteria.EnvType == environmentTypeId &&
				criteria.EnvId == nil && criteria.AppId == nil && (criteria.ResId == nil || *criteria.ResId == resId) && criteria.Class == "default" {
				message.Debug("Matching criteria already exist")
				return nil
			}
		}
	}

	createMatchingCriteriaResp, err := p.Client.CreateResourceDefinitionCriteriaWithResponse(ctx, p.OrganizationId, defId, client.MatchingCriteriaRuleRequest{
		EnvType: &environmentTypeId,
		ResId:   &resId,
	})
	if err != nil {
		return fmt.Errorf("failed to create matching criteria: %w", err)
	}
	if createMatchingCriteriaResp.StatusCode() == 409 {
		return fmt.Errorf("same matching criteria applied to another resource definition: %s, remove them from it before proceeding", createMatchingCriteriaResp.JSON409.Message)
	}
	if createMatchingCriteriaResp.StatusCode() != 200 {
		return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", createMatchingCriteriaResp.StatusCode(), string(createMatchingCriteriaResp.Body))
	}

	return nil
}
