package platform

import (
	"fmt"

	humanitec "github.com/humanitec/humanitec-go-autogen"
)

type HumanitecPlatform struct {
	OrganizationId string
	Client         *humanitec.Client
}

func NewHumanitecPlatform(token string) (*HumanitecPlatform, error) {
	humClient, err := humanitec.NewClient(&humanitec.Config{
		Token: token,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create humanitec client: %w", err)
	}
	return &HumanitecPlatform{Client: humClient}, nil
}
