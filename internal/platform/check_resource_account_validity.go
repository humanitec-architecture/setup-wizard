package platform

import (
	"context"
	"fmt"
)

type ResourceAccountValidityCheckResult struct {
	Warnings []string
	Error    *string
}

func (p *HumanitecPlatform) CheckResourceAccountValidity(ctx context.Context, accountId string) (ResourceAccountValidityCheckResult, error) {
	result := ResourceAccountValidityCheckResult{}
	resp, err := p.Client.CheckResourceAccountWithResponse(ctx, p.OrganizationId, accountId)
	if err != nil {
		return result, fmt.Errorf("failed to check resource account: %w", err)
	}

	switch resp.StatusCode() {
	case 200:
		warnings := resp.JSON200.Warnings
		if warnings != nil {
			result.Warnings = *warnings
		}
		return result, nil
	case 400:
		errorMessage := fmt.Sprintf("%s - %s", resp.JSON400.Error, resp.JSON400.Message)
		result.Error = &errorMessage
		return result, nil
	default:
		return result, fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", resp.StatusCode(), string(resp.Body))
	}
}
