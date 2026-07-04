# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-02-24

### Added
- Custom base64 builder for improved encoding performance

### Improved
- Enhanced data collection capabilities with better performance
- Optimized Base64 encoding implementation

## [1.0.0] - 2026-02-18

### Initial Release
- Full WinRM/WS-Management client implementation for Go
- Persistent shell support with command execution
- Multiple authentication methods:
  - Basic authentication
  - NTLM (via Azure/go-ntlmssp)
  - Kerberos/SPNEGO (via jcmturner/gokrb5)
  - Certificate-based authentication
- WMI query support (WMIQuery, WMIEnumerate, WMIGet)
- JSON and CSV output parsing with generic unmarshaling
- Shell pooling for concurrent command execution
- PowerShell script encoding (UTF-16LE Base64) with proper character handling
- Batch command execution with sequential processing
- Comprehensive error handling with typed errors
- Retry logic with configurable backoff
- Per-request context-based timeouts
- Thread-safe concurrent operations
- Support for Go 1.26+ with generics

### Features
- **Client Configuration**: Flexible endpoint, auth, TLS, and retry settings
- **Multiple Transport Layers**: Support for HTTP/2 disabled (WinRM compatibility), NTLM, Kerberos, and certificate auth
- **Command Execution**: Create shells, execute commands, stream results
- **Data Parsing**: Built-in JSON and CSV parsing with struct mapping (using `json` tags)
- **Error Classification**: Temporary errors, auth errors, parse errors with helpful context
- **Test Coverage**: httptest-based mock server testing (no real Windows host required for unit tests)

### Dependencies
- `github.com/Azure/go-ntlmssp` - NTLM authentication support
- `github.com/jcmturner/gokrb5/v8` - Kerberos SPNEGO client
- `github.com/google/uuid` - UUID generation for WinRM operations
- `github.com/stretchr/testify` - Test utilities

---

## Unreleased

### Planned
- CredSSP authentication implementation
- Additional WMI operation enhancements
- Performance optimizations for large-scale batch operations
