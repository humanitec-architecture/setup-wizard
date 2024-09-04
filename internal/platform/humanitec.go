package platform

import (
	"fmt"
	"net/http"
	"time"

	humanitec "github.com/humanitec/humanitec-go-autogen"
	"github.com/justinrixx/retryhttp"
)

type HumanitecPlatform struct {
	OrganizationId string
	Client         *humanitec.Client
}

func NewHumanitecPlatform(token string) (*HumanitecPlatform, error) {
	httpClient := &http.Client{Timeout: time.Second * 10}
	httpClient = wrapHttpClientWithRetries(httpClient)

	humClient, err := humanitec.NewClient(&humanitec.Config{
		Token:  token,
		Client: httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create humanitec client: %w", err)
	}
	return &HumanitecPlatform{Client: humClient}, nil
}

func wrapHttpClientWithRetries(c *http.Client) *http.Client {
	c.Transport = retryhttp.New(
		retryhttp.WithTransport(c.Transport),
		retryhttp.WithMaxRetries(5),
		retryhttp.WithDelayFn(retryhttp.DefaultDelayFn),
		retryhttp.WithShouldRetryFn(retryhttp.CustomizedShouldRetryFn(retryhttp.CustomizedShouldRetryFnOptions{
			IdempotentMethods: []string{http.MethodGet, http.MethodDelete, http.MethodHead, http.MethodPut},
			RetryableStatusCodes: []int{
				http.StatusInternalServerError,
				http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
			},
		})),
	)
	return c
}
