package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/adjscent/http-whois/pkg/logger"
	"github.com/adjscent/http-whois/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)

const (
	path = "/api/v1/whois"
)

func main() {
	router := gin.Default()

	router.POST(path, func(c *gin.Context) {
		var json model.WhoisRequest
		if err := c.BindJSON(&json); err != nil {
			logger.L.Error(err)
			c.JSON(http.StatusBadRequest, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusBadRequest}})

			return
		}

		rootDomain := getRootDomainFromDomain(json.Domain)

		rawResult, err := whois.Whois(rootDomain, "whois.iana.org")
		if err != nil {
			logger.L.Error(err)
			c.JSON(http.StatusInternalServerError, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusInternalServerError}})

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
			logger.L.Error(err)
			c.JSON(http.StatusInternalServerError, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusInternalServerError}})

			return
		}

		now := time.Now()
		expiryDate := result.Domain.ExpirationDateInTime
		if expiryDate == nil {
			err := fmt.Errorf("failed to parse expiration date: %w", err)
			logger.L.Error(err)
			c.JSON(http.StatusInternalServerError, model.WhoisResponse{Error: model.Error{Message: err.Error(), Code: http.StatusInternalServerError}})

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

func getRootDomainFromDomain(domain string) string {
	domain = strings.TrimSpace(domain)

	if domain == "" {
		return ""
	}
	domainSplit := strings.Split(domain, ".")
	domainLen := len(domainSplit)

	//For domains that only contain number
	if isStringDigit(domainSplit[domainLen-1]) {
		return domain
	}

	rootDomain := domain
	if domainLen > 2 {
		rootDomain = domainSplit[domainLen-2] + "." + domainSplit[domainLen-1]
	}

	return rootDomain
}

func isStringDigit(s string) bool {
	re := regexp.MustCompile(`^\d+$`) // Matches a string containing only digits
	return re.MatchString(s)
}
