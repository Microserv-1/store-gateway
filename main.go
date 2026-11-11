package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "gateway_request_duration_seconds", Help: "Gateway request duration", Buckets: prometheus.DefBuckets}, []string{"route", "method"})

func newHandler(secret []byte, routes map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	health := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"gateway"}`))
	}
	mux.HandleFunc("GET /health-check", health)
	mux.HandleFunc("GET /ready", health)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 8 * time.Second, MaxIdleConnsPerHost: 32}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "//") {
			http.Error(w, "Invalid path", 400)
			return
		}
		prefix := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
		target, exists := routes[prefix]
		if !exists {
			http.NotFound(w, r)
			return
		}
		started := time.Now()
		defer func() { duration.WithLabelValues(prefix, r.Method).Observe(time.Since(started).Seconds()) }()
		public := r.Method == "POST" && (r.URL.Path == "/accounts" || r.URL.Path == "/auth/login")
		outgoing := make(http.Header)
		for _, name := range []string{"Content-Type", "Accept"} {
			if v := r.Header.Get(name); v != "" {
				outgoing.Set(name, v)
			}
		}
		if prefix == "products" {
			outgoing.Set("X-Cache-Control", r.Header.Get("X-Cache-Control"))
		}
		if !public {
			fields := strings.Fields(r.Header.Get("Authorization"))
			if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
				unauthorized(w)
				return
			}
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(fields[1], claims, func(t *jwt.Token) (any, error) { return secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("store-auth"), jwt.WithAudience("store-api"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
			if err != nil || !token.Valid || claims.Subject == "" || claims.IssuedAt == nil {
				unauthorized(w)
				return
			}
			outgoing.Set("Authorization", "Bearer "+fields[1])
			outgoing.Set("X-Account-ID", claims.Subject)
		}
		if target == "" {
			http.Error(w, "Service not configured", 503)
			return
		}
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			http.Error(w, "Invalid upstream configuration", 503)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		proxy := &httputil.ReverseProxy{
			Rewrite: func(p *httputil.ProxyRequest) { p.SetURL(u); p.Out.Header = outgoing; p.Out.Host = u.Host }, Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				var sizeErr *http.MaxBytesError
				if errors.As(err, &sizeErr) {
					http.Error(w, "Request too large", 413)
					return
				}
				if e, ok := err.(net.Error); ok && e.Timeout() {
					http.Error(w, "Upstream timeout", 504)
				} else {
					http.Error(w, "Service unavailable", 503)
				}
			},
		}
		requestID := make([]byte, 16)
		_, _ = rand.Read(requestID)
		w.Header().Set("X-Request-ID", hex.EncodeToString(requestID))
		w.Header().Set("X-Gateway-Instance", os.Getenv("HOSTNAME"))
		proxy.ServeHTTP(w, r)
		slog.Info("request", "route", prefix, "method", r.Method, "duration_ms", time.Since(started).Milliseconds())
	})
	return mux
}
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "Invalid or missing token", 401)
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		panic("JWT_SECRET must contain at least 32 characters")
	}
	prometheus.MustRegister(duration)
	routes := map[string]string{}
	for prefix, key := range map[string]string{"accounts": "ACCOUNT_URL", "auth": "AUTH_URL", "products": "PRODUCT_URL", "orders": "ORDER_URL", "exchanges": "EXCHANGE_URL"} {
		routes[prefix] = os.Getenv(key)
	}
	server := &http.Server{Addr: ":8000", Handler: newHandler(secret, routes), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
