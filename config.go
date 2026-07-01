// Package winrm provides a modern, high-performance WinRM client library for Go.
// It supports persistent shells, multiple authentication methods (Basic, NTLM, Kerberos, CredSSP),
// and automatic PowerShell encoding with JSON/CSV/XML parsing capabilities.
package winrm

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strconv"
	"time"
)

// Config holds the configuration for connecting to a WinRM server.
type Config struct {
	// Host is the hostname or IP address of the Windows server.
	Host string

	// Port is the WinRM port (default: 5985 for HTTP, 5986 for HTTPS).
	Port int

	// UseHTTPS enables HTTPS connection (port 5986).
	UseHTTPS bool

	// InsecureSkipVerify skips TLS certificate verification (for testing).
	InsecureSkipVerify bool

	// CACert is the CA certificate for TLS verification (PEM encoded).
	CACert []byte

	// ClientCert is the client certificate for mutual TLS (PEM encoded).
	ClientCert []byte

	// ClientKey is the client private key for mutual TLS (PEM encoded).
	ClientKey []byte

	// Auth contains the authentication configuration.
	Auth AuthConfig

	// Timeouts for various operations.
	ConnectTimeout time.Duration
	SendTimeout    time.Duration
	ReceiveTimeout time.Duration

	// OperationTimeout is the WinRM operation timeout sent to the server.
	OperationTimeout time.Duration

	// MaxEnvelopeSize is the maximum envelope size for WinRM messages (default: 153600).
	MaxEnvelopeSize int

	// Locale is the locale for WinRM operations (default: en-US).
	Locale string

	// Retry configuration for transient errors.
	RetryConfig *RetryConfig

	// Custom HTTP transport (optional, overrides other transport settings).
	Transport http.RoundTripper
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Type AuthType

	// Username for authentication (for NTLM, can be "domain\\user" or just "user").
	Username string

	// Password for authentication.
	Password string

	// Domain for NTLM/Kerberos authentication (optional, can be in username).
	Domain string

	// SPN (Service Principal Name) for Kerberos authentication.
	SPN string

	// KerberosConfigFile is the path to krb5.conf for Kerberos.
	KerberosConfigFile string

	// KerberosCredCache is the path to credential cache for Kerberos.
	KerberosCredCache string
}

// AuthType represents the type of authentication.
type AuthType int

const (
	// AuthTypeBasic uses HTTP Basic authentication.
	// Requires HTTPS for security, credentials sent in clear text (base64).
	AuthTypeBasic AuthType = iota

	// AuthTypeNTLM uses NTLM (NTLMv2) authentication.
	// Works over HTTP and HTTPS, credentials are hashed.
	AuthTypeNTLM

	// AuthTypeKerberos uses Kerberos authentication.
	// Requires proper Kerberos configuration and ticket.
	AuthTypeKerberos

	// AuthTypeCredSSP uses CredSSP authentication.
	// Allows credential delegation, requires HTTPS.
	AuthTypeCredSSP

	// AuthTypeCertificate uses client certificate authentication.
	// Requires HTTPS and client certificate configuration.
	AuthTypeCertificate
)

// String returns the string representation of AuthType.
func (a AuthType) String() string {
	switch a {
	case AuthTypeBasic:
		return "Basic"
	case AuthTypeNTLM:
		return "NTLM"
	case AuthTypeKerberos:
		return "Kerberos"
	case AuthTypeCredSSP:
		return "CredSSP"
	case AuthTypeCertificate:
		return "Certificate"
	default:
		return "Unknown"
	}
}

// RetryConfig holds retry configuration for transient errors.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (default: 3).
	MaxRetries int

	// InitialDelay is the initial delay before the first retry (default: 500ms).
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries (default: 10s).
	MaxDelay time.Duration

	// Multiplier is the multiplier for exponential backoff (default: 2.0).
	Multiplier float64
}

// AuthBasic creates a Basic authentication configuration.
// Note: Basic auth sends credentials in base64 (not encrypted), use only with HTTPS.
func AuthBasic(username, password string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeBasic,
		Username: username,
		Password: password,
	}
}

// AuthNTLM creates an NTLM authentication configuration.
// Username can be "user" or "domain\\user" format.
func AuthNTLM(username, password string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeNTLM,
		Username: username,
		Password: password,
	}
}

// AuthNTLMWithDomain creates an NTLM authentication configuration with explicit domain.
func AuthNTLMWithDomain(domain, username, password string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeNTLM,
		Domain:   domain,
		Username: username,
		Password: password,
	}
}

// AuthKerberos creates a Kerberos authentication configuration.
// Requires proper Kerberos setup (krb5.conf, kinit, etc.).
func AuthKerberos(username, password, realm string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeKerberos,
		Username: username,
		Password: password,
		Domain:   realm,
	}
}

// AuthKerberosWithKeytab creates Kerberos auth using keytab file.
func AuthKerberosWithKeytab(username, realm, keytabPath string) AuthConfig {
	return AuthConfig{
		Type:              AuthTypeKerberos,
		Username:          username,
		Domain:            realm,
		KerberosCredCache: keytabPath,
	}
}

// AuthCredSSP creates a CredSSP authentication configuration.
// CredSSP allows credential delegation for multi-hop scenarios.
// Requires HTTPS connection.
func AuthCredSSP(username, password string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeCredSSP,
		Username: username,
		Password: password,
	}
}

// AuthCredSSPWithDomain creates CredSSP auth with explicit domain.
func AuthCredSSPWithDomain(domain, username, password string) AuthConfig {
	return AuthConfig{
		Type:     AuthTypeCredSSP,
		Domain:   domain,
		Username: username,
		Password: password,
	}
}

// AuthCertificate creates certificate-based authentication.
// Requires client certificate and key to be set in Config.
func AuthCertificate() AuthConfig {
	return AuthConfig{
		Type: AuthTypeCertificate,
	}
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Port:             5985,
		ConnectTimeout:   30 * time.Second,
		SendTimeout:      60 * time.Second,
		ReceiveTimeout:   60 * time.Second,
		OperationTimeout: 60 * time.Second,
		MaxEnvelopeSize:  153600,
		Locale:           "en-US",
		RetryConfig: &RetryConfig{
			MaxRetries:   3,
			InitialDelay: 500 * time.Millisecond,
			MaxDelay:     10 * time.Second,
			Multiplier:   2.0,
		},
	}
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:   3,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
	}
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.Host == "" {
		return ErrInvalidConfig("host is required")
	}

	// Username validation (not required for certificate auth)
	if c.Auth.Type != AuthTypeCertificate && c.Auth.Username == "" {
		return ErrInvalidConfig("username is required")
	}

	// Certificate auth requires client cert
	if c.Auth.Type == AuthTypeCertificate {
		if len(c.ClientCert) == 0 || len(c.ClientKey) == 0 {
			return ErrInvalidConfig("client certificate and key required for certificate authentication")
		}
	}

	// CredSSP requires HTTPS
	if c.Auth.Type == AuthTypeCredSSP && !c.UseHTTPS {
		return ErrInvalidConfig("CredSSP authentication requires HTTPS")
	}

	return nil
}

// GetPort returns the configured port or the default based on UseHTTPS.
func (c *Config) GetPort() int {
	if c.Port != 0 {
		return c.Port
	}
	if c.UseHTTPS {
		return 5986
	}
	return 5985
}

// GetTLSConfig returns the TLS configuration based on settings.
func (c *Config) GetTLSConfig() *tls.Config {
	if !c.UseHTTPS {
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	// Add CA cert if provided
	if len(c.CACert) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(c.CACert)
		tlsConfig.RootCAs = pool
	}

	// Add client cert if provided
	if len(c.ClientCert) > 0 && len(c.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	return tlsConfig
}

// GetEndpoint returns the full WinRM endpoint URL.
func (c *Config) GetEndpoint() string {
	scheme := "http"
	if c.UseHTTPS {
		scheme = "https"
	}
	return scheme + "://" + c.Host + ":" + strconv.Itoa(c.GetPort()) + "/wsman"
}

// Clone creates a deep copy of the Config.
// Note: The Transport field (http.RoundTripper) is shared, not deep-copied,
// since transports are typically reusable and not safely cloneable.
func (c *Config) Clone() *Config {
	clone := *c
	if c.RetryConfig != nil {
		rc := *c.RetryConfig
		clone.RetryConfig = &rc
	}
	if len(c.CACert) > 0 {
		clone.CACert = make([]byte, len(c.CACert))
		copy(clone.CACert, c.CACert)
	}
	if len(c.ClientCert) > 0 {
		clone.ClientCert = make([]byte, len(c.ClientCert))
		copy(clone.ClientCert, c.ClientCert)
	}
	if len(c.ClientKey) > 0 {
		clone.ClientKey = make([]byte, len(c.ClientKey))
		copy(clone.ClientKey, c.ClientKey)
	}
	return &clone
}
