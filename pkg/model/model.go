package model

import "time"

type WhoisRequest struct {
	Domain string `json:"domain" binding:"required"`
}

type WhoisData struct {
	IsValid     bool      `json:"is_valid"`
	CurrentDate time.Time `json:"current_date"`
	ExpiryDate  time.Time `json:"expiry"`
	Expired     bool      `json:"expired"`
	RootDomain  string    `json:"root_domain"`
	WhoisServer string    `json:"whois_server"`
	Raw         string    `json:"raw"`
}

type WhoisResponse struct {
	Data  WhoisData `json:"data,omitempty"`
	Error Error     `json:"error,omitempty"`
}

type Error struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}
