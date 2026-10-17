# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

MCPJungle is a self-hosted MCP gateway: a single Go binary that registers upstream MCP servers (stdio, streamable HTTP, SSE) and re-exposes all their tools, prompts and resources through one MCP endpoint, plus a REST API, a CLI and a dev-mode web dashboard.

## Commands

**Build the dashboard bundle first.** `internal/dashboardui/embed.go` has `//go:embed dist`, and `internal/dashboardui/dist` is generated and gitignored. On a fresh clone every `go build` / `go test` fails with `pattern dist: no matching files found` until you run:

```bash
bash ./scripts/build-dashboard.sh   # runs npm ci (if needed) + npm run build in web/dashboard, copies dist into internal/dashboardui/dist
```

Run it again after any frontend change, then restart the Go process, because the assets are embedded at compile time.

```bash
go run . start                       # dev mode on :8080, SQLite at ./mcpjungle.db, auto-initialized
go run . start --enterprise          # enterprise mode (needs `mcpjungle init-server` afterwards)
go run . <cmd> --registry http://127.0.0.1:8080   # any other CLI command talks to a running server

go test ./...                                          # all tests
go test ./internal/service/mcp                         # one package
go test ./internal/service/mcp -run TestSplitServerToolName -v   # one test
go test ./internal/e2e ./internal/api                  # API + end-to-end (dashboard, tool groups, modes, OAuth)

golangci-lint run          # v2 config in .golangci.yml; formatters: gci, gofmt, gofumpt, goimports
golangci-lint run --fix

./scripts/test-mcpjungle.sh            # sanity/integration script: builds bin/mcpjungle, then starts local servers and mock upstreams on ports 18080-18084 (needs curl)
./scripts/test-api-error-responses.sh  # checks HTTP error codes of the REST API against an isolated server

cd web/dashboard && npm run typecheck  # frontend has no lint script
cd web/dashboard && npm run dev        # Vite on :5173, proxies /api to the Go server on :8080

goreleaser build --single-target --clean --snapshot   # local release-style build
```

The PR template asks for `go test ./...` and `scripts/test-mcpjungle.sh` to pass.

Test notes:
- `internal/e2e` registers `@modelcontextprotocol/server-everything` through `npx` as a stdio upstream and skips itself when `npx` is not on PATH.
- Tests use in-memory SQLite (`pkg/testhelpers.CreateTestDB`, or `gorm.Open(sqlite.Open(":memory:"))` plus `migrations.Migrate`). Each pooled connection to `:memory:` gets its own empty database, so a test that fires concurrent requests must call `SetMaxOpenConns(1)` on the underlying `*sql.DB`. Otherwise requests fail with "server is not initialized" or missing tables.
- `cmd` `TestResolveTargetDirForExport/invalid_permissions_for_directory_creation` fails when tests run as root, because root ignores `0o000` permissions.

GoReleaser's `before.hooks` run `build-dashboard.sh`, `go test -v ./...`, `golangci-lint run` and `go mod tidy`, so a lint error blocks a release. The version is injected through ldflags into `pkg/version.Version`.

## Architecture

### One binary, CLI over HTTP
`main.go` calls `cmd.Execute()` (cobra). `start` runs the server. Every other command is a thin HTTP client: it uses the `client/` package against the REST API at `--registry` (default `http://127.0.0.1:8080`), or at `registry_url` / `access_token` from `~/.mcpjungle.conf` (`cmd/config`).

- Every top-level command (added with `rootCmd.AddCommand`) must set `Annotations["group"]` to `basic` or `advanced`, or the root help's `groupCommands()` returns an error. `Annotations["order"]` is optional: it sets the position within the group, and commands without it are listed last.
- The CLI resolves `${VAR}` placeholders in JSON config files (`register --conf`, `create ... --conf`) itself, through `internal/configresolver`, before it sends the request.
- The CLI's upstream OAuth flow starts its own localhost callback server (`cmd/register.go`).

### Server wiring
`cmd/start.go:runStartServer` builds everything:
1. Connects the DB (`internal/db`). SQLite is the default, with fallback to a legacy `mcp.db`. Postgres is used when `DATABASE_URL` or `POSTGRES_HOST` (+ `POSTGRES_*`, including `*_FILE` variants) is set.
2. Runs `internal/migrations.Migrate`: GORM `AutoMigrate` over every model. **A new model must be added there.**
3. Builds two mcp-go proxy servers, then the services, then `api.NewServer`.

Layering:
- `internal/model`: GORM models.
- `pkg/types`: wire structs shared by the server and `client/` (the API contract).
- `internal/service/*`: business logic.
- `internal/api`: gin handlers. Services wrap the `pkg/apierrors` sentinels (`ErrNotFound`, `ErrInvalidInput`), and `handleServiceError` in `internal/api/errors.go` maps them to 404, 400 or 500. Errors are JSON `{"error": ..., "code"?: ...}`.

All routes are in `internal/api/server.go`:
- `/mcp`: streamable HTTP proxy.
- `/sse` + `/message`: SSE proxy.
- `/v0/groups/:name/{mcp,sse,message}`: per-tool-group proxies.
- `/api/v0/...`: REST API, split into a user group and an admin group.
- `/api/dashboard/...` and `/`: the dashboard.
- `/health`, `/metadata`, `/init`, and `/metrics` (when OTEL is on).

### MCP gateway (`internal/service/mcp`)
- **Two proxy MCP servers.** Entities from SSE upstreams go on `SseMcpProxyServer`, served at `/sse`. Everything else (stdio, streamable HTTP) goes on `McpProxyServer`, served at `/mcp`. Any code that adds or removes a tool, prompt or resource must pick the proxy by its upstream server's `Transport`.
- **Canonical names** are `<server>__<name>` (separator `__` in `util.go`), so server names may not contain `__` or end in `_`. Proxy handlers in `proxy.go` split the name, load the server from the DB, get a session, strip client headers (`request.Header = nil`, see issue #252) and forward the call.
- **The DB is the source of truth; the proxy is an in-memory mirror.**
  - `initMCPProxyServer` reloads every *enabled* tool, prompt and resource from the DB at startup.
  - Registration (`server.go:registerMcpServer`) connects to the upstream, saves the server, then registers its tools (required) and its prompts/resources (best-effort).
  - Enable, disable and deregister update both the DB and the proxy.
- **Sessions** (`session_result.go`, `session_manager.go`):
  - `session_mode: stateless` (default) opens a new upstream connection per call and closes it afterwards.
  - `stateful` keeps one cached client per server in `SessionManager`. It is dropped on idle timeout (`SESSION_IDLE_TIMEOUT_SEC`), on connection-type errors (`invalidateOnError`), on deregister and on shutdown.
  - The idle timeout in code differs from the docs. When `SESSION_IDLE_TIMEOUT_SEC` is unset or negative, `NewSessionManager` falls back to `DefaultSessionIdleTimeoutSec` (1 hour), and only `0` disables the timeout. README and `docs/reference/environment-variables.mdx` say the default `-1` means "no timeout".
- **Upstream OAuth** (`upstream_oauth.go`): pending sessions and tokens are stored in the DB (`model/upstream_oauth.go`). The dashboard can't run a localhost callback the way the CLI does, so it uses the server's `/api/dashboard/oauth/callback` and polls `/api/dashboard/oauth/session/:id`.

### Tool groups (`internal/service/toolgroup`)
Each group gets its own pair of mcp-go servers, holding only the group's effective tools (explicitly listed tools, plus included servers, minus excluded tools).

The group service stays in sync with global enable/disable/deregister through `MCPService.SetToolAdditionCallback` / `SetToolDeletionCallback`. The API layer keeps one mcp-go `SSEServer` per group (`groupSseServers`). Groups don't support prompts yet.

### Server modes (`model.ServerMode`)
The mode is persisted in the DB (`ServerConfig`). `start` refuses to run in a different mode than the one the DB was initialized with. `production` is a deprecated alias for `enterprise`.

- **development** (default):
  - auto-initialized on start;
  - no auth anywhere;
  - dashboard enabled;
  - OTEL off by default.
- **enterprise** (`--enterprise` or `SERVER_MODE=enterprise`):
  - `init-server` creates the admin user;
  - `/api/v0` needs a user bearer token, and admin routes need the admin role;
  - the MCP proxy needs an *MCP client* token, and `ProxyToolFilter` (list) plus `authorizeProxyServerAccess` (call) limit a client to its allowed servers;
  - users and MCP clients endpoints are enterprise-only;
  - dashboard routes return 404;
  - OTEL on by default (`OTEL_ENABLED` overrides).

Middleware (`internal/api/middleware.go`) stores the mode under the gin key `"mode"`. mcp-go handlers never see the gin context, so `checkAuthForMcpProxyAccess` also puts `"mode"` and `"client"` into `c.Request.Context()` with `context.WithValue`. Proxy code reads them from there.

### Dashboard
React 18 + Vite in `web/dashboard`. It is a single page that switches sections in state, with no router. Its handlers are `internal/api/dashboard*.go`, and read-side response shaping lives in `internal/service/dashboard`.

Dashboard APIs must never expose secrets: tokens, OAuth secrets, env var values, header values. Return keys only, and don't reuse `/api/v0/server_configs` without sanitizing it. The full workflow and the steps for adding an endpoint are in `docs/developers/dashboard-development.mdx`.

### Telemetry
Use the `telemetry.CustomMetrics` interface everywhere. A no-op implementation is used when OTEL is disabled, so callers never check whether metrics are on.

## Conventions
- The project follows minimalism: make the smallest change that works without breaking other behavior, and skip speculative extras (`docs/developers/development.mdx`).
- User-facing CLI/API changes need doc updates in `README.md` and the Mintlify site in `docs/` (MDX, configured by `docs/docs.json`; style rules in `docs/AGENTS.md`).
- Don't commit `vendor/`. `go.mod` / `go.sum` are the source of truth.
