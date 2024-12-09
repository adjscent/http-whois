# http-whois


This is a http proxy for the whois.

The server file is in cmd/main.go

The client file is in pkg/client.

Example usage for client
```golang
	ctx := context.Background()
	logger.SetLogger(logrus.New())

	c := client.NewClient("your-api-key", "http://localhost:8080")

	whois1, err := c.Whois(ctx, "google.com")
	if err != nil {
		logger.L.Error(err)
		return
	}

	logger.L.Info(whois1)
```

building
```bash
docker build -t http-whois .
```

run with docker compose
```bash
docker network create traefik_proxy
docker compose up
```