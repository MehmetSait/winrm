package winrm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/go-ntlmssp"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Client represents a WinRM client connection.
// It is safe for concurrent use from multiple goroutines.
type Client struct {
	config     *Config
	httpClient *http.Client
	endpoint   string
	mu         sync.RWMutex
}

// NewClient creates a new WinRM client with the given configuration.
// The client maintains a connection pool for efficient reuse.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Apply defaults
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = 60 * time.Second
	}
	if config.ReceiveTimeout == 0 {
		config.ReceiveTimeout = 60 * time.Second
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = 60 * time.Second
	}
	if config.MaxEnvelopeSize == 0 {
		config.MaxEnvelopeSize = 153600
	}
	if config.Locale == "" {
		config.Locale = "en-US"
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create HTTP transport with connection pooling
	transport := config.Transport
	if transport == nil {
		transport = createTransport(config)
	}

	// Wrap transport for authentication
	finalTransport := wrapTransportWithAuth(transport, config)

	client := &Client{
		config:   config,
		endpoint: config.GetEndpoint(),
		httpClient: &http.Client{
			Transport: finalTransport,
			Timeout:   0, // We handle timeouts per-request with context
		},
	}

	return client, nil
}

// createTransport creates an optimized HTTP transport.
func createTransport(config *Config) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false, // WinRM doesn't support HTTP/2
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: config.ReceiveTimeout,
		TLSClientConfig:       config.GetTLSConfig(),
		DisableCompression:    false,
	}
}

// wrapTransportWithAuth wraps the transport with the appropriate authentication handler.
func wrapTransportWithAuth(transport http.RoundTripper, config *Config) http.RoundTripper {
	switch config.Auth.Type {
	case AuthTypeNTLM:
		return &ntlmTransport{
			transport: transport,
			domain:    config.Auth.Domain,
			username:  config.Auth.Username,
			password:  config.Auth.Password,
		}
	case AuthTypeBasic:
		return &basicAuthTransport{
			transport: transport,
			username:  config.Auth.Username,
			password:  config.Auth.Password,
		}
	case AuthTypeKerberos:
		return &kerberosTransport{
			transport: transport,
			config:    config,
		}
	case AuthTypeCredSSP:
		return &credsspTransport{
			transport: transport,
			config:    config,
		}
	case AuthTypeCertificate:
		// Certificate auth is handled by TLS config
		return transport
	default:
		return transport
	}
}

// CreateShell creates a new persistent shell on the remote server.
func (c *Client) CreateShell() (*Shell, error) {
	return c.CreateShellContext(context.Background())
}

// CreateShellContext creates a new persistent shell with context support.
func (c *Client) CreateShellContext(ctx context.Context) (*Shell, error) {
	envelope, err := buildCreateShellEnvelope(
		c.endpoint,
		c.config.MaxEnvelopeSize,
		c.config.OperationTimeout,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.sendWithRetry(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to create shell: %w", err)
	}

	shellID, err := parseCreateShellResponse(resp)
	if err != nil {
		return nil, err
	}

	return &Shell{
		client:  c,
		shellID: shellID,
	}, nil
}

// sendWithRetry sends a request with exponential backoff retry for transient errors.
func (c *Client) sendWithRetry(ctx context.Context, body []byte) ([]byte, error) {
	retryConfig := c.config.RetryConfig
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	var lastErr error
	delay := retryConfig.InitialDelay

	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay = time.Duration(float64(delay) * retryConfig.Multiplier)
				if delay > retryConfig.MaxDelay {
					delay = retryConfig.MaxDelay
				}
			}
		}

		resp, err := c.send(ctx, body)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if !IsTemporary(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}

// send sends a SOAP request to the WinRM server.
func (c *Client) send(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("User-Agent", "Go-WinRM/2.0")
	req.ContentLength = int64(len(body))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			return nil, ErrTimeout
		}
		if isConnectionError(err) {
			return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	// Pre-allocate buffer based on Content-Length if available
	var buf bytes.Buffer
	if resp.ContentLength > 0 {
		buf.Grow(int(resp.ContentLength))
	}

	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	respBody := buf.Bytes()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse SOAP fault from response
		if faultErr := parseSOAPFaultFromResponse(respBody); faultErr != nil {
			return nil, faultErr
		}
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return respBody, nil
}

// Close closes the client and releases all resources.
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// Endpoint returns the WinRM endpoint URL.
func (c *Client) Endpoint() string {
	return c.endpoint
}

// Config returns the client configuration (read-only).
func (c *Client) Config() Config {
	return *c.config
}

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// isConnectionError checks if an error is a connection error.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// Authentication transports

// ntlmTransport wraps an http.RoundTripper with NTLM authentication.
type ntlmTransport struct {
	transport http.RoundTripper
	domain    string
	username  string
	password  string
}

func (t *ntlmTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	negotiator := ntlmssp.Negotiator{
		RoundTripper: t.transport,
	}

	reqClone := req.Clone(req.Context())

	// Build username with domain if provided
	username := t.username
	if t.domain != "" {
		username = t.domain + "\\" + t.username
	}
	reqClone.SetBasicAuth(username, t.password)

	return negotiator.RoundTrip(reqClone)
}

// basicAuthTransport wraps an http.RoundTripper with Basic authentication.
type basicAuthTransport struct {
	transport http.RoundTripper
	username  string
	password  string
}

func (t *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqClone := req.Clone(req.Context())
	reqClone.SetBasicAuth(t.username, t.password)
	return t.transport.RoundTrip(reqClone)
}

// kerberosTransport wraps an http.RoundTripper with Kerberos (SPNEGO) authentication.
// Supports both password-based and keytab-based authentication.
// The SPNEGO client is lazily initialized on first request and reused for subsequent calls.
type kerberosTransport struct {
	transport http.RoundTripper
	config    *Config

	mu       sync.Mutex
	spnegoCl *spnego.Client
	initErr  error
}

func (t *kerberosTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	spnegoCl, err := t.getSPNEGOClient()
	if err != nil {
		return nil, err
	}

	reqClone := req.Clone(req.Context())
	return spnegoCl.Do(reqClone)
}

func (t *kerberosTransport) getSPNEGOClient() (*spnego.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.spnegoCl != nil {
		return t.spnegoCl, nil
	}
	if t.initErr != nil {
		return nil, t.initErr
	}

	cfgPath := t.config.Auth.KerberosConfigFile
	if cfgPath == "" {
		cfgPath = "/etc/krb5.conf"
	}

	cfg, err := krb5config.Load(cfgPath)
	if err != nil {
		t.initErr = fmt.Errorf("kerberos: failed to load config from %q: %w", cfgPath, err)
		return nil, t.initErr
	}

	realm := t.config.Auth.Domain
	username := t.config.Auth.Username

	var cl *krb5client.Client
	if t.config.Auth.KerberosCredCache != "" {
		kt, err := keytab.Load(t.config.Auth.KerberosCredCache)
		if err != nil {
			t.initErr = fmt.Errorf("kerberos: failed to load keytab from %q: %w", t.config.Auth.KerberosCredCache, err)
			return nil, t.initErr
		}
		cl = krb5client.NewWithKeytab(username, realm, kt, cfg)
	} else {
		cl = krb5client.NewWithPassword(username, realm, t.config.Auth.Password, cfg)
	}

	if err := cl.Login(); err != nil {
		t.initErr = fmt.Errorf("kerberos: login failed: %w", err)
		return nil, t.initErr
	}

	spn := t.config.Auth.SPN
	if spn == "" {
		spn = "WSMAN/" + t.config.Host
	}

	t.spnegoCl = spnego.NewClient(cl, &http.Client{Transport: t.transport}, spn)
	return t.spnegoCl, nil
}

// credsspTransport wraps an http.RoundTripper with CredSSP authentication.
// Note: Full CredSSP implementation requires additional dependencies.
type credsspTransport struct {
	transport http.RoundTripper
	config    *Config
}

func (t *credsspTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// CredSSP implementation would require:
	// - TLS negotiation
	// - SPNEGO wrapping
	// - Credential delegation support
	//
	// For now, return error indicating CredSSP is not yet implemented
	return nil, fmt.Errorf("credssp authentication not yet implemented - use NTLM auth")
}

// Quick helper methods for simple use cases

// Run runs a single command and returns the output.
// Creates a temporary shell that is closed after the command completes.
func (c *Client) Run(ctx context.Context, command string) (*CommandResult, error) {
	shell, err := c.CreateShellContext(ctx)
	if err != nil {
		return nil, err
	}
	defer shell.Close()

	return shell.ExecuteContext(ctx, command)
}

// RunPowerShell runs a PowerShell script and returns the output.
// The script is automatically encoded as UTF-16LE Base64.
// Creates a temporary shell that is closed after completion.
func (c *Client) RunPowerShell(ctx context.Context, script string) (*CommandResult, error) {
	shell, err := c.CreateShellContext(ctx)
	if err != nil {
		return nil, err
	}
	defer shell.Close()

	return shell.ExecutePowerShellContext(ctx, script)
}

// Pool represents a pool of persistent shells for high-throughput scenarios.
// The pool maintains pre-created shells to avoid the overhead of creating
// new shells for each command.
type Pool struct {
	client  *Client
	shells  chan *Shell
	maxSize int
	mu      sync.Mutex
	closed  bool
}

// NewPool creates a new shell pool with the specified size.
// Shells are pre-created for immediate availability.
func (c *Client) NewPool(size int) (*Pool, error) {
	if size <= 0 {
		size = 5
	}

	pool := &Pool{
		client:  c,
		shells:  make(chan *Shell, size),
		maxSize: size,
	}

	// Pre-create shells
	for i := 0; i < size; i++ {
		shell, err := c.CreateShell()
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to create shell for pool: %w", err)
		}
		pool.shells <- shell
	}

	return pool, nil
}

// Get gets a shell from the pool.
// If the pool is empty, it waits until a shell is available or context is cancelled.
func (p *Pool) Get(ctx context.Context) (*Shell, error) {
	select {
	case shell := <-p.shells:
		if shell.IsClosed() {
			return p.client.CreateShellContext(ctx)
		}
		return shell, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Put returns a shell to the pool.
// If the shell is closed or the pool is full, the shell is discarded.
func (p *Pool) Put(shell *Shell) {
	if shell == nil || shell.closed {
		return
	}

	select {
	case p.shells <- shell:
	default:
		shell.Close()
	}
}

// Size returns the current number of available shells in the pool.
func (p *Pool) Size() int {
	return len(p.shells)
}

// Close closes all shells in the pool and releases resources.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	close(p.shells)
	for shell := range p.shells {
		shell.Close()
	}
	return nil
}
