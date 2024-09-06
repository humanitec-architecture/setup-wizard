package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/humanitec/humanitec-go-autogen/client"
)

var resourceTypesWithInternalSecrets = map[string]bool{
	"k8s-cluster":   true,
	"k8s-namespace": true,
	"logging":       true,
}

func (p *HumanitecPlatform) CheckInternalSecrets(ctx context.Context) (bool, error) {
	defsResp, err := p.Client.ListResourceDefinitionsWithResponse(ctx, p.OrganizationId, &client.ListResourceDefinitionsParams{})
	if err != nil {
		return false, fmt.Errorf("failed to list resource definitions: %w", err)
	}

	if defsResp.StatusCode() != http.StatusOK {
		return false, fmt.Errorf("humanitec API returned unexpected status code: %d with body when fetching resource definitions: %s", defsResp.StatusCode(), string(defsResp.Body))
	}

	for _, def := range *defsResp.JSON200 {
		if internal, ok := resourceTypesWithInternalSecrets[def.Type]; !internal || !ok {
			if def.DriverInputs != nil && def.DriverInputs.SecretRefs != nil {
				if !def.IsDefault && secretRefsContainInternalSecret(*def.DriverInputs.SecretRefs) {
					return true, nil
				}
			}
		}
	}

	appsResp, err := p.Client.ListApplicationsWithResponse(ctx, p.OrganizationId)
	if err != nil {
		return false, fmt.Errorf("failed to list applications: %w", err)
	}

	if appsResp.StatusCode() != http.StatusOK {
		return false, fmt.Errorf("humanitec API returned unexpected status code: %d with body when fetching applications: %s", defsResp.StatusCode(), string(defsResp.Body))
	}

	for _, app := range *appsResp.JSON200 {
		valuesAppResp, err := p.Client.GetOrgsOrgIdAppsAppIdValuesWithResponse(ctx, p.OrganizationId, app.Id)
		if err != nil {
			return false, fmt.Errorf("failed to list values for application '%s': %w", app.Id, err)
		}

		if valuesAppResp.StatusCode() != http.StatusOK {
			return false, fmt.Errorf("humanitec API returned unexpected status code: %d with body when fetching values of application '%s': %s", defsResp.StatusCode(), app.Id, string(defsResp.Body))
		}

		for _, values := range *valuesAppResp.JSON200 {
			if values.IsSecret && *values.SecretStoreId == "humanitec" {
				return true, nil
			}
		}

		for _, env := range app.Envs {
			valuesEnvResp, err := p.Client.GetOrgsOrgIdAppsAppIdEnvsEnvIdValuesWithResponse(ctx, p.OrganizationId, app.Id, env.Id)
			if err != nil {
				return false, fmt.Errorf("failed to list values for environment '%s/%s': %w", app.Id, env.Id, err)
			}

			if valuesEnvResp.StatusCode() != http.StatusOK {
				return false, fmt.Errorf("humanitec API returned unexpected status code: %d with body when fetching values of environment '%s/%s': %s", defsResp.StatusCode(), app.Id, env.Id, string(defsResp.Body))
			}

			for _, values := range *valuesEnvResp.JSON200 {
				if values.IsSecret && *values.SecretStoreId == "humanitec" {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func secretRefsContainInternalSecret(secretRefs map[string]interface{}) bool {
	for _, subRef := range secretRefs {
		if containsInternalSecrets(subRef) {
			return true
		}
	}
	return false
}

func containsInternalSecrets(secretRefs interface{}) bool {
	switch typed := secretRefs.(type) {
	case map[string]interface{}:
		for _, subRef := range typed {
			if isSecretRef, secretRef := isSecretReference(typed); isSecretRef {
				if secretRef.Store == "humanitec" {
					return true
				}
			} else {
				if containsInternalSecrets(subRef) {
					return true
				}
			}
		}
	case []map[string]interface{}:
		for _, subRef := range typed {
			if containsInternalSecrets(subRef) {
				return true
			}
		}
	case []SecretReference:
		for _, subRef := range typed {
			if containsInternalSecrets(subRef) {
				return true
			}
		}
	case SecretReference:
		return typed.Store == "humanitec"
	}
	return false
}

type SecretReference struct {
	Store string `json:"store"`
	Ref   string `json:"ref"`
}

func isSecretReference(data map[string]interface{}) (bool, SecretReference) {
	dataJson, _ := json.Marshal(data)
	var secretRef SecretReference
	dec := json.NewDecoder(bytes.NewReader(dataJson))
	dec.DisallowUnknownFields()
	return dec.Decode(&secretRef) == nil, secretRef
}
