package platform

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/utils"
	"github.com/score-spec/score-go/loader"
	"github.com/score-spec/score-go/types"
	"gopkg.in/yaml.v2"
)

//go:embed test_workload.score.yaml
var testWorkload []byte

var deploymentMessage = "Test deployment from humctl-wizard"

func (p *HumanitecPlatform) DeployTestApplication(ctx context.Context, applicationId, environmentId string) (string, string, error) {
	var scoreSpec map[string]any
	err := yaml.Unmarshal(testWorkload, &scoreSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to unmarshal test workload: %w", err)
	}

	scoreSpec, err = mapScoreSpec(scoreSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to map score spec: %w", err)
	}

	convertToSetResp, err := p.Client.ConvertScoreToSetWithResponse(ctx, p.OrganizationId, client.ConvertScoreToSetBody{
		Spec: scoreSpec,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to convert score to set: %w", err)
	}
	if convertToSetResp.StatusCode() != 200 {
		return "", "", fmt.Errorf("failed to convert score to set: humanitec API returned unexpected status code: %d with body: %s", convertToSetResp.StatusCode(), string(convertToSetResp.Body))
	}
	deploymentSet := *convertToSetResp.JSON200

	deltaRequest, err := setToDeltaRequest(&deploymentSet, environmentId)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert set to delta request: %w", err)
	}

	createDeltaResp, err := p.Client.PostOrgsOrgIdAppsAppIdDeltasWithResponse(ctx, p.OrganizationId, applicationId, *deltaRequest)
	if err != nil {
		return "", "", fmt.Errorf("failed to create delta: %w", err)
	}
	if createDeltaResp.StatusCode() != 200 {
		return "", "", fmt.Errorf("failed to create delta: humanitec API returned unexpected status code: %d with body: %s", createDeltaResp.StatusCode(), string(createDeltaResp.Body))
	}
	var delta client.DeltaResponse
	if err := json.Unmarshal(createDeltaResp.Body, &delta); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal delta response: %w", err)
	}

	var createPipelineRunRequest client.PipelineRunCreateByTriggerCriteriaBody
	err = createPipelineRunRequest.FromPipelineRunCreateByDeploymentRequestCriteriaBody(client.PipelineRunCreateByDeploymentRequestCriteriaBody{
		Comment: &deploymentMessage,
		DeltaId: &delta.Id,
		EnvId:   &environmentId,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to convert pipeline run create by deployment request criteria body: %w", err)
	}

	createPipelineRunResp, err := p.Client.CreatePipelineRunByTriggerCriteriaWithResponse(ctx, p.OrganizationId, applicationId, &client.CreatePipelineRunByTriggerCriteriaParams{}, createPipelineRunRequest)
	if err != nil {
		return "", "", fmt.Errorf("failed to create pipeline run: %w", err)
	}
	if createPipelineRunResp.StatusCode() != 201 {
		return "", "", fmt.Errorf("failed to create pipeline run: humanitec API returned unexpected status code: %d with body: %s", createPipelineRunResp.StatusCode(), string(createPipelineRunResp.Body))
	}
	pipelineRun := *createPipelineRunResp.JSON201

	return pipelineRun.PipelineId, pipelineRun.Id, nil
}

func setToDeltaRequest(set *client.WorkloadArtefactVersionDeploymentSet, envID string) (*client.DeltaRequest, error) {
	add := map[string]*client.ModuleRequest{}
	shared := []client.UpdateActionRequest{}

	for n, m := range set.Modules {
		mr := &client.ModuleRequest{}
		if err := utils.ReEncode(m, &mr); err != nil {
			return nil, fmt.Errorf("failed to reencode module: %s, %w", n, err)
		}

		add[n] = mr
	}

	for n, m := range set.Shared {
		var value interface{}
		if err := utils.ReEncode(m, &value); err != nil {
			return nil, fmt.Errorf("failed to reencode shared: %s, %w", n, err)
		}

		operation := "add"
		path := fmt.Sprintf("/%s", n)
		shared = append(shared, client.UpdateActionRequest{
			Op:    &operation,
			Path:  &path,
			Value: &value,
		})
	}

	return &client.DeltaRequest{
		Metadata: &client.DeltaMetadataRequest{
			EnvId: &envID,
		},
		Modules: &client.ModuleDeltasRequest{
			Add: &add,
		},
		Shared: &shared,
	}, nil
}

func mapScoreSpec(specMap map[string]interface{}) (map[string]interface{}, error) {
	var scoreSpec types.Workload
	if err := loader.MapSpec(&scoreSpec, specMap); err != nil {
		return nil, fmt.Errorf("failed to map score file: %w", err)
	}

	// if err := loader.Normalize(&scoreSpec, workingDir); err != nil {
	// 	return nil, fmt.Errorf("failed to normalize score file: %w", err)
	// }

	var normalizedMap map[string]interface{}
	if err := utils.ReEncode(scoreSpec, &normalizedMap); err != nil {
		return nil, fmt.Errorf("failed to reencode score spec: %w", err)
	}

	return normalizedMap, nil
}
