package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
)

type selectResourceDefinitionCriteria func(client.ResourceDefinitionResponse) bool

func AllSelectResourceDefinitionsCriteria(criteria ...selectResourceDefinitionCriteria) selectResourceDefinitionCriteria {
	return func(resDef client.ResourceDefinitionResponse) bool {
		for _, criteria := range criteria {
			if !criteria(resDef) {
				return false
			}
		}
		return true
	}
}

func (p* HumanitecPlatform) SelectResourceDefinitions(ctx context.Context, criteria selectResourceDefinitionCriteria) ([]client.ResourceDefinitionResponse, error) {
	resDefs, err := p.Client.ListResourceDefinitionsWithResponse(ctx, p.OrganizationId, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching resource definitions: %w", err)
	}
	if resDefs.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("list resource definitions returned unexpected status code: %d with body: %s", resDefs.StatusCode(), string(resDefs.Body))
	}

	var selectedResDefs []client.ResourceDefinitionResponse
	for _, resDef := range *resDefs.JSON200 {
		if criteria(resDef) {
			selectedResDefs = append(selectedResDefs, resDef)
		}
	}
	return selectedResDefs, nil
}

