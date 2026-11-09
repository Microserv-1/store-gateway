package main

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedProxyStripsUntrustedIdentity(t *testing.T) {
	secret := []byte(strings.Repeat("a", 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Account-ID") != "account-a" {
			t.Errorf("forged identity forwarded")
		}
		if r.Header.Get("X-Internal-Auth-Key") != "" {
			t.Errorf("internal credential forwarded")
		}
		if r.URL.RawQuery != "currency=BRL" {
			t.Errorf("query lost")
		}
		w.WriteHeader(201)
	}))
	defer upstream.Close()
	handler := newHandler(secret, map[string]string{"orders": upstream.URL})
	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "account-a", Issuer: "store-auth", Audience: jwt.ClaimStrings{"store-api"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/orders?currency=BRL", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Account-ID", "victim")
	req.Header.Set("X-Internal-Auth-Key", "stolen")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	if result.Code != 201 {
		t.Fatalf("status %d: %s", result.Code, result.Body.String())
	}
}

func TestRejectsInvalidCredentials(t *testing.T) {
	secret := []byte(strings.Repeat("a", 32))
	handler := newHandler(secret, map[string]string{"accounts": "http://127.0.0.1:1"})
	now := time.Now()
	for _, tc := range []struct {
		name   string
		claims jwt.RegisteredClaims
		key    []byte
	}{
		{"expired", jwt.RegisteredClaims{Subject: "a", Issuer: "store-auth", Audience: jwt.ClaimStrings{"store-api"}, IssuedAt: jwt.NewNumericDate(now.Add(-time.Hour)), ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute))}, secret},
		{"wrong-key", jwt.RegisteredClaims{Subject: "a", Issuer: "store-auth", Audience: jwt.ClaimStrings{"store-api"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, []byte(strings.Repeat("b", 32))},
		{"wrong-audience", jwt.RegisteredClaims{Subject: "a", Issuer: "store-auth", Audience: jwt.ClaimStrings{"other"}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, tc.claims).SignedString(tc.key)
			req := httptest.NewRequest("GET", "/accounts/me", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Fatalf("wanted 401 got %d", rec.Code)
			}
		})
	}
}
