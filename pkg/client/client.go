package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/adjscent/http-whois/pkg/logger"
	"github.com/adjscent/http-whois/pkg/model"
	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	APIKey  string
	BaseURL string
}

const (
	retry = 3
)

func NewClient(apiKey string, baseURL string) *Client {
	return &Client{
		APIKey:  apiKey,
		BaseURL: baseURL,
	}
}

func (c *Client) Whois(ctx context.Context, domain string) (*model.WhoisResponse, error) {
	requestData := model.WhoisRequest{Domain: domain}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		logger.L.Error(err)
		return nil, err
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/v1/whois", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.L.Error(err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", c.APIKey)

	client := retryablehttp.NewClient()
	client.RetryMax = retry
	client.RetryWaitMin = 1 * time.Second                // Minimum wait time between retries
	client.RetryWaitMax = 5 * time.Second                // Maximum wait time between retries
	client.CheckRetry = retryablehttp.DefaultRetryPolicy // Retry on 429 and 5xx statuses by default
	client.HTTPClient.Timeout = 10 * time.Second

	response, err := client.Do(req)
	if err != nil {
		logger.L.Error(err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	var target model.WhoisResponse
	if err := json.NewDecoder(response.Body).Decode(&target); err != nil {
		logger.L.Error(err)
		return nil, err
	}

	return &target, nil
}
