# Store Gateway

Go reverse proxy with JWT validation, bounded request bodies, upstream timeouts, structured logs and Prometheus metrics. Public API routes: only `POST /accounts` and `POST /auth/login`. Health endpoints are also public. Protected prefixes: `/accounts`, `/auth`, `/products`, `/orders`, `/exchanges`.

Required: `JWT_SECRET` (32+ characters). Destinations: `ACCOUNT_URL`, `AUTH_URL`, `PRODUCT_URL`, `ORDER_URL`, `EXCHANGE_URL`. Missing/unavailable destination returns 503. API method, path and query are preserved. Caller identity/internal credential headers are discarded; verified identity is forwarded as `X-Account-ID` alongside the original Bearer token.

Run `go test ./...`, `go run .`, or `docker build -t store-gateway .`. Go 1.23+ is required; the Dockerfile builds with Go 1.24. Jenkinsfile and `k8s/k8s.yaml` belong to this repository.

`X-Gateway-Instance` identifies the proxy pod; upstream `X-Served-By` can demonstrate Account balancing. Services must validate JWT independently when directly reachable. See [store-root](https://github.com/Microserv-1/store-root) and [documentation](https://github.com/Microserv-1/store-docs-a). Contracts await review against official exercise statements.
