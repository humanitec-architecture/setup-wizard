package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretRefsContainInternalSecret(t *testing.T) {
	var tests = []struct {
		name           string
		secretRefs     map[string]interface{}
		expectedResult bool
	}{
		{
			name:           "some internal secret",
			expectedResult: true,
			secretRefs: map[string]interface{}{
				"source": map[string]interface{}{},
				"terraform": map[string]interface{}{
					"tokens": map[string]interface{}{
						"domain.io": map[string]interface{}{
							"store": "humanitec",
							"ref":   "orgs/testing-org-bianca/resources/defs/my-s3-to-delete/driver_secrets/terraform/tokens/domain.io/.value",
						},
					},
				},
			},
		},
		{
			name:           "no internal secret",
			expectedResult: false,
			secretRefs: map[string]interface{}{
				"source": map[string]interface{}{},
				"terraform": map[string]interface{}{
					"tokens": map[string]interface{}{
						"domain.io": map[string]interface{}{
							"store": "my-store",
							"ref":   "orgs/testing-org-bianca/resources/defs/my-s3-to-delete/driver_secrets/terraform/tokens/domain.io/.value",
						},
					},
				},
			},
		},
		{
			name:           "mixed secret",
			expectedResult: true,
			secretRefs: map[string]interface{}{
				"source": map[string]interface{}{},
				"terraform": map[string]interface{}{
					"tokens": map[string]interface{}{
						"domain.io": map[string]interface{}{
							"store": "my-store",
							"ref":   "orgs/testing-org-bianca/resources/defs/my-s3-to-delete/driver_secrets/terraform/tokens/domain.io/.value",
						},
						"other.domain.io": map[string]interface{}{
							"store": "humanitec",
							"ref":   "orgs/testing-org-bianca/resources/defs/my-s3-to-delete/driver_secrets/terraform/tokens/domain.io/.value",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, secretRefsContainInternalSecret(tc.secretRefs), tc.expectedResult)
		})
	}
}
