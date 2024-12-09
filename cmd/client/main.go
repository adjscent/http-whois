package main

import (
	"context"

	"github.com/adjscent/http-whois/pkg/client"
	"github.com/adjscent/http-whois/pkg/logger"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()
	logger.SetLogger(logrus.New())

	c := client.NewClient("your-api-key", "http://localhost:8080")

	whois1, err := c.Whois(ctx, "google.com")
	if err != nil {
		logger.L.Error(err)
		return
	}

	logger.L.Info(whois1)

	whois2, err := c.Whois(ctx, "invalidgoogle.com")
	if err != nil {
		logger.L.Error(err)
		return
	}

	logger.L.Info(whois2)
}
