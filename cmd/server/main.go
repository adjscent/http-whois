package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adjscent/http-whois/pkg/logger"
	"github.com/adjscent/http-whois/pkg/model"
	"github.com/avast/retry-go"
	"github.com/gin-gonic/gin"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"go.uber.org/multierr"
)

const (
	path = "/api/v1/whois"
)

func main() {
	router := gin.Default()

	router.POST(path, func(c *gin.Context) {
		var json model.WhoisRequest
		if err := c.BindJSON(&json); err != nil {
			err := multierr.Append(err, fmt.Errorf("request: %v", json))
			logger.L.Error(err)
			c.JSON(http.StatusBadRequest, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusBadRequest}})

			return
		}

		logger.L.Infof("processing domain: %v", json.Domain)

		rootDomain := getRootDomain(json.Domain)

		// do not remove the whois server
		var rawResult string

		if err := retry.Do(
			func() error {
				result, err2 := whois.Whois(rootDomain, "whois.iana.org")
				if err2 != nil {
					return err2
				}

				rawResult = result

				return nil
			}, retry.Attempts(3)); err != nil {
			err := multierr.Append(err, fmt.Errorf("request: %v", json))
			logger.L.Error(err)
			c.JSON(http.StatusBadRequest, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusBadRequest}})

			return
		}

		isValid := checkValidFromRaw(rawResult)
		if !isValid {
			c.JSON(http.StatusOK, model.WhoisResponse{
				Data: model.WhoisData{
					IsValid:    false,
					RootDomain: rootDomain,
					Raw:        rawResult,
				}})

			return
		}

		result, err := whoisparser.Parse(rawResult)
		if err != nil {
			err := multierr.Append(err, fmt.Errorf("request: %v", json))
			logger.L.Error(err)
			c.JSON(http.StatusBadRequest, model.WhoisResponse{Data: model.WhoisData{IsValid: false, RootDomain: rootDomain, Raw: rawResult}, Error: model.Error{Message: err.Error(), Code: http.StatusBadRequest}})

			return
		}

		now := time.Now()
		expiryDate := result.Domain.ExpirationDateInTime
		if expiryDate == nil {
			err := fmt.Errorf("failed to parse expiration date")
			err = multierr.Append(err, fmt.Errorf("request: %v", json))
			logger.L.Error(err)
			c.JSON(http.StatusBadRequest, model.WhoisResponse{Data: model.WhoisData{IsValid: false, RootDomain: rootDomain, Raw: rawResult}, Error: model.Error{Message: err.Error(), Code: http.StatusBadRequest}})

			return
		}
		expired := expiryDate.Before(now)

		c.JSON(http.StatusOK, model.WhoisResponse{
			Data: model.WhoisData{
				IsValid:     true,
				CurrentDate: now,
				ExpiryDate:  *expiryDate,
				Expired:     expired,
				RootDomain:  rootDomain,
				WhoisServer: result.Domain.WhoisServer,
				Raw:         rawResult,
			}})

		return
	})

	err := router.Run(":8080")
	if err != nil {
		logger.L.Error(err)
		panic(err)
	}
}

func checkValidFromRaw(raw string) bool {
	if raw == "" || strings.Contains(raw, "No match for") || strings.Contains(raw, "Not found") {
		return false
	}

	return true
}

func getRootDomain(fqdn string) string {
	list := publicsuffix.DefaultList

	domain, err := publicsuffix.DomainFromListWithOptions(list, fqdn, publicsuffix.DefaultFindOptions)
	if err != nil {
		logger.L.Errorf("err: %v, ignoring suffix errors, returning original fqdn", err)

		return fqdn
	}

	return domain
}
