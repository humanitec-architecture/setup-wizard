package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/humanitec/humctl-wizard/internal/utils"
)

var ErrPipelineRunFailed = fmt.Errorf("pipeline run failed")

func (p *HumanitecPlatform) WaitForPipelineRunComplete(ctx context.Context, applicationId, pipelineId, pipelineRunId string) error {
	for {
		getPipelineRunResp, err := p.Client.GetPipelineRunWithResponse(ctx, p.OrganizationId, applicationId, pipelineId, pipelineRunId)
		if err != nil {
			return fmt.Errorf("failed to get pipeline run: %w", err)
		}
		if getPipelineRunResp.StatusCode() != 200 {
			return fmt.Errorf("humanitec API returned unexpected status code: %d with body: %s", getPipelineRunResp.StatusCode(), string(getPipelineRunResp.Body))
		}
		pipelineRun := getPipelineRunResp.JSON200

		if pipelineRun.Status == "queued" || pipelineRun.Status == "executing" {
			utils.Sleep(ctx, 1*time.Second)
			continue
		}

		if pipelineRun.Status == "failed" {
			return ErrPipelineRunFailed
		}

		break
	}
	return nil
}
