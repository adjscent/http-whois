package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	apiKey := "testkey"
	baseURL := "http://example.com"
	client := NewClient(apiKey, baseURL)

	assert.Equal(t, apiKey, client.APIKey)
	assert.Equal(t, baseURL, client.BaseURL)
}
