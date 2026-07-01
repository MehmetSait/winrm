# AGENTS.md

Guide for AI agents working in this WinRM client library codebase.

## Project Overview

Go library (`github.com/MehmetSait/winrm`) implementing a WinRM/WS-Management client for managing Windows servers via PowerShell remoting. Requires **Go 1.26+** (uses generics). Supports persistent shells, multiple auth methods (Basic, NTLM, Kerberos, Certificate), WMI queries, and JSON/CSV output parsing.

## Commands

```bash
go build ./...      # build all packages
go test ./...       # run all tests (uses httptest mock server, no real Windows host needed)
go vet ./...        # lint
gofmt -w .          # format (note: wmi.go is currently unformatted in the repo)
```

There is no Makefile, no CI config, and no linter beyond `go vet`. The example under `examples/basic/` requires a real Windows host via `WINRM_HOST`/`WINRM_USERNAME`/`WINRM_PASSWORD` env vars and is not run by `go test`.

## Architecture

The library is a single flat package (`winrm`) with no subpackages. Data flows through these layers:

1. **`config.go`** — `Config`, `AuthConfig`, `RetryConfig` types, defaults, validation, TLS setup, endpoint URL construction.
2. **`client.go`** — `Client` owns the `http.Client` and endpoint. Creates HTTP transport (HTTP/2 explicitly disabled — WinRM doesn't support it), wraps it with an auth-specific `http.RoundTripper` (`ntlmTransport`, `basicAuthTransport`, `kerberosTransport`, `credsspTransport`). Handles `send`/`sendWithRetry`. Also contains `Pool` (shell pool) and quick `Run`/`RunPowerShell` helpers.
3. **`shell.go`** — `Shell` (persistent remote process), `Command` (single command lifecycle), `CommandResult`, `Batch` (sequential command runner), and `EncodePowerShellScript`.
4. **`soap.go`** — SOAP envelope **templates** (via `text/template`) for shell operations + response **parsing** (via `encoding/xml`). All WinRM protocol XML lives here.
5. **`wmi.go`** — WMI/WS-Management operations. Separate SOAP templates and XML namespaces from shell operations. `Client.WMIQuery`/`WMIEnumerate`/`WMIGet` methods.
6. **`parse.go`** — JSON and CSV parsing helpers, including generic `UnmarshalCSVTo[T]`.
7. **`errors.go`** — Sentinel errors, typed errors (`WinRMError`, `SOAPFault`, `PowerShellError`, `ParseError`), and classifier helpers (`IsTemporary`, `IsAuthError`, etc.).

**Control flow**: `Client.sendWithRetry` → `Client.send` (HTTP POST with SOAP body) → auth transport `RoundTrip` → response parsed by soap.go/wmi.go parsers. Command execution is a multi-step WS-Management sequence: Create Shell → Execute Command → Receive (loop until Done) → Signal Terminate → Delete Shell.

## Key Conventions & Gotchas

### SOAP request building vs. response parsing
- **Requests are built with `text/template`** (`template.Must` pre-parsed vars in `soap.go`/`wmi.go`), NOT `encoding/xml` marshaling. Templates embed `{{.Namespaces}}` as a raw string constant.
- **Responses are parsed with `encoding/xml`** unmarshaling into typed structs (`soapEnvelope`, `wmiSoapEnvelope`).
- Shell operations and WMI operations use **different XML namespace sets** (`xmlNamespaces` vs `wmiXMLNamespaces`) — don't mix them.

### PowerShell encoding
- `NewPowerShellCommand` encodes scripts as **UTF-16LE Base64** (`EncodePowerShellScript` in `shell.go`) to handle non-ASCII (e.g., Turkish characters). This is mandatory for correct special-character handling.
- It also **prepends `$ProgressPreference = 'SilentlyContinue';`** to every script to suppress progress bars that would otherwise pollute stderr.

### Authentication
- **CredSSP is NOT implemented** — `credsspTransport.RoundTrip` always returns an error. Use NTLM instead.
- **Kerberos SPNEGO client is lazily initialized** on first request (mutex-guarded) and reused. Config path defaults to `/etc/krb5.conf`.
- **NTLM** uses `Azure/go-ntlmssp` negotiator; domain is prepended to username as `domain\user` if provided.
- **Certificate auth** is handled entirely by TLS config (no transport wrapper).

### Custom errorAs helper
`client.go` has a hand-rolled `errorAs` function instead of using `errors.As` from the stdlib. It only handles `*net.Error` and `**net.OpError`. If you need to check other error types, use `errors.As` directly rather than extending this helper.

### Timeouts
- `http.Client.Timeout` is set to `0` — **all timeouts are handled per-request via `context.Context`**.
- `OperationTimeout` is sent to the server as an ISO 8601 duration string (`formatTimeout` in `soap.go`).

### Concurrency
- `Client`, `Shell`, and `Command` are safe for concurrent use (each has its own `sync.Mutex`/`sync.RWMutex`).
- A single `Shell` **serializes** command execution via its mutex — for concurrent commands, use `Client.NewPool` to get multiple shells.

### CSV-to-struct mapping
`UnmarshalCSVTo[T]` and `RunAndUnmarshalCSVTo[T]` use **`json` struct tags** (not `csv` tags) for column mapping. Internally, each CSV row is converted to a `map[string]string`, marshaled to JSON, then unmarshaled into the target struct.

### Testing
- Tests in `winrm_test.go` use `httptest.NewServer` to mock a WinRM server — no real Windows host required.
- The mock server inspects request body strings (`Contains` "Create"/"Command"/"Receive"/"Delete") to route responses.
- `TestMockWinRMServer` creates a real `Client` then **overrides `client.endpoint`** to point at the test server — this is the pattern for integration-style tests.
- Tests use table-driven style with `t.Run` subtests. No testify assertions are used despite it being an indirect dependency.

### Pool behavior
`Pool.Get` checks if a returned shell is closed and creates a new one if so. `Pool.Put` silently discards closed/full shells. `Pool.Close` closes the channel and drains/closes all shells.

## Module Path

The module is `github.com/MehmetSait/winrm`. The local working directory is under a `roksit` org path but the Go module path is `MehmetSait`. Imports must use `github.com/MehmetSait/winrm`.
