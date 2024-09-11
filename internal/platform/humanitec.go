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
	httpClient := &http.Client{Timeout: time.Second * 10, Transport: http.DefaultTransport}
	httpClient = wrapHttpClientWithCatchingExpiredToken(httpClient)
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


type CatchExpiredHumanitecToken struct {
	Proxied http.RoundTripper
}

func (c *CatchExpiredHumanitecToken) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.Proxied.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("humanitec token expired or you don't have enough permissions. Please login, e.g. using humctl login")
	}
	return resp, nil
}

func wrapHttpClientWithCatchingExpiredToken(c *http.Client) *http.Client {
	c.Transport = &CatchExpiredHumanitecToken{Proxied: c.Transport}
	return c
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
