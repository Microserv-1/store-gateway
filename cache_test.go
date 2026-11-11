package main

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProductCacheBypassCrossesGateway(t *testing.T) {
	secret := []byte(strings.Repeat("c", 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cache-Control") != "no-cache" {
			t.Error("cache bypass was discarded")
		}
		if r.Header.Get("X-Internal-Auth-Key") != "" {
			t.Error("internal credential leaked")
		}
		w.Header().Set("X-Cache", "BYPASS")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	now := time.Now()
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "account-a", Issuer: "store-auth", Audience: jwt.ClaimStrings{"store-api"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}).SignedString(secret)
	request := httptest.NewRequest("GET", "/products", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Cache-Control", "no-cache")
	request.Header.Set("X-Internal-Auth-Key", "must-not-forward")
	response := httptest.NewRecorder()
	newHandler(secret, map[string]string{"products": upstream.URL}).ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("X-Cache") != "BYPASS" {
		t.Fatal("cache bypass response not preserved")
	}
}
