package winrm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthBasic(t *testing.T) {
	auth := AuthBasic("user", "pass")
	if auth.Type != AuthTypeBasic {
		t.Errorf("expected AuthTypeBasic, got %v", auth.Type)
	}
	if auth.Username != "user" {
		t.Errorf("expected user, got %s", auth.Username)
	}
	if auth.Password != "pass" {
		t.Errorf("expected pass, got %s", auth.Password)
	}
}
func TestAuthNTLM(t *testing.T) {
	auth := AuthNTLM("user", "pass")
	if auth.Type != AuthTypeNTLM {
		t.Errorf("expected AuthTypeNTLM, got %v", auth.Type)
	}
}
func TestAuthNTLMWithDomain(t *testing.T) {
	auth := AuthNTLMWithDomain("DOMAIN", "user", "pass")
	if auth.Domain != "DOMAIN" {
		t.Errorf("expected DOMAIN, got %s", auth.Domain)
	}
}
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "empty host",
			config:  &Config{},
			wantErr: true,
		},
		{
			name:    "empty username",
			config:  &Config{Host: "localhost"},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &Config{
				Host: "localhost",
				Auth: AuthBasic("user", "pass"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestConfigGetPort(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected int
	}{
		{"default HTTP", &Config{}, 5985},
		{"explicit port", &Config{Port: 1234}, 1234},
		{"HTTPS default", &Config{UseHTTPS: true}, 5986},
		{"HTTPS with explicit", &Config{UseHTTPS: true, Port: 9999}, 9999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.GetPort(); got != tt.expected {
				t.Errorf("GetPort() = %v, want %v", got, tt.expected)
			}
		})
	}
}
func TestConfigGetEndpoint(t *testing.T) {
	config := &Config{Host: "192.168.1.1", Port: 5985}
	endpoint := config.GetEndpoint()
	expected := "http://192.168.1.1:5985/wsman"
	if endpoint != expected {
		t.Errorf("GetEndpoint() = %v, want %v", endpoint, expected)
	}
	config.UseHTTPS = true
	config.Port = 5986
	endpoint = config.GetEndpoint()
	expected = "https://192.168.1.1:5986/wsman"
	if endpoint != expected {
		t.Errorf("GetEndpoint() = %v, want %v", endpoint, expected)
	}
}
func TestEncodePowerShell(t *testing.T) {
	script := "Get-Date"
	encoded := EncodePowerShellScript(script)
	// The encoded string should be valid base64
	if encoded == "" {
		t.Error("EncodePowerShellScript returned empty string")
	}
	// Test with Turkish characters
	turkishScript := "Write-Host 'Merhaba Dünya'"
	encodedTurkish := EncodePowerShellScript(turkishScript)
	if encodedTurkish == "" {
		t.Error("EncodePowerShellScript returned empty string for Turkish text")
	}
}
func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{"empty", "", false},
		{"valid object", `{"name": "test"}`, false},
		{"valid array", `[{"name": "a"}, {"name": "b"}]`, false},
		{"invalid json", `{invalid}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result interface{}
			err := UnmarshalJSON(tt.data, &result)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestUnmarshalCSV(t *testing.T) {
	csv := `"Name","Value","Status"
"Test1","100","Active"
"Test2","200","Inactive"`
	rows, err := UnmarshalCSV(csv)
	if err != nil {
		t.Fatalf("UnmarshalCSV() error = %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(rows))
	}
	if rows[0]["Name"] != "Test1" {
		t.Errorf("expected Test1, got %s", rows[0]["Name"])
	}
	if rows[0]["Value"] != "100" {
		t.Errorf("expected 100, got %s", rows[0]["Value"])
	}
}
func TestUnmarshalCSVWithTypeInfo(t *testing.T) {
	csv := `#TYPE System.Object
"Name","Value"
"Test","123"`
	rows, err := UnmarshalCSV(csv)
	if err != nil {
		t.Fatalf("UnmarshalCSV() error = %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 row (type info line should be skipped), got %d", len(rows))
	}
}
func TestParseCSVLine(t *testing.T) {
	tests := []struct {
		line     string
		expected []string
	}{
		{`a,b,c`, []string{"a", "b", "c"}},
		{`"a","b","c"`, []string{"a", "b", "c"}},
		{`"a,b","c"`, []string{"a,b", "c"}},
		{`"a""b",c`, []string{`a"b`, "c"}},
	}
	for _, tt := range tests {
		result := parseCSVLine(tt.line)
		if len(result) != len(tt.expected) {
			t.Errorf("parseCSVLine(%q) = %v, want %v", tt.line, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("parseCSVLine(%q)[%d] = %q, want %q", tt.line, i, result[i], tt.expected[i])
			}
		}
	}
}
func TestFormatTimeout(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "PT30S"},
		{60 * time.Second, "PT1M"},
		{90 * time.Second, "PT1M30S"},
		{5 * time.Minute, "PT5M"},
	}
	for _, tt := range tests {
		result := formatTimeout(tt.duration)
		if result != tt.expected {
			t.Errorf("formatTimeout(%v) = %s, want %s", tt.duration, result, tt.expected)
		}
	}
}
func TestBuildCreateShellEnvelope(t *testing.T) {
	envelope, err := buildCreateShellEnvelope("http://test/wsman", 153600, 60*time.Second)
	if err != nil {
		t.Fatalf("buildCreateShellEnvelope() error = %v", err)
	}
	if !strings.Contains(string(envelope), "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create") {
		t.Error("envelope should contain Create action")
	}
	if !strings.Contains(string(envelope), "http://test/wsman") {
		t.Error("envelope should contain endpoint")
	}
}
func TestParseCreateShellResponse(t *testing.T) {
	xmlResp := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:ShellId>ABC-123-DEF</rsp:ShellId>
    </rsp:Shell>
  </s:Body>
</s:Envelope>`
	shellID, err := parseCreateShellResponse([]byte(xmlResp))
	if err != nil {
		t.Fatalf("parseCreateShellResponse() error = %v", err)
	}
	if shellID != "ABC-123-DEF" {
		t.Errorf("expected ABC-123-DEF, got %s", shellID)
	}
}
func TestIsTemporary(t *testing.T) {
	if IsTemporary(nil) {
		t.Error("nil error should not be temporary")
	}
	if !IsTemporary(ErrTimeout) {
		t.Error("ErrTimeout should be temporary")
	}
	if !IsTemporary(ErrConnectionFailed) {
		t.Error("ErrConnectionFailed should be temporary")
	}
	if IsTemporary(ErrAuthenticationFailed) {
		t.Error("ErrAuthenticationFailed should not be temporary")
	}
}
func TestCommandResult(t *testing.T) {
	result := &CommandResult{
		stdout:   []byte("hello"),
		stderr:   []byte("error"),
		ExitCode: 0,
	}
	if result.Stdout() != "hello" {
		t.Errorf("expected hello, got %s", result.Stdout())
	}
	if result.Stderr() != "error" {
		t.Errorf("expected error, got %s", result.Stderr())
	}
	if !result.Success() {
		t.Error("expected success")
	}
	result.ExitCode = 1
	if result.Success() {
		t.Error("expected failure")
	}
}

// Mock HTTP server for integration-like tests
func TestMockWinRMServer(t *testing.T) {
	shellID := "TEST-SHELL-123"
	commandID := "TEST-CMD-456"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Read the full request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
			return
		}
		defer r.Body.Close()

		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		if strings.Contains(string(body), "Create") {
			// Create Shell response
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:ShellId>` + shellID + `</rsp:ShellId>
    </rsp:Shell>
  </s:Body>
</s:Envelope>`))
		} else if strings.Contains(string(body), "Command") {
			// Execute Command response
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:CommandResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:CommandId>` + commandID + `</rsp:CommandId>
    </rsp:CommandResponse>
  </s:Body>
</s:Envelope>`))
		} else if strings.Contains(string(body), "Receive") {
			// Receive output response
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:ReceiveResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:Stream Name="stdout" CommandId="` + commandID + `">SGVsbG8gV29ybGQ=</rsp:Stream>
      <rsp:CommandState CommandId="` + commandID + `" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
        <rsp:ExitCode>0</rsp:ExitCode>
      </rsp:CommandState>
    </rsp:ReceiveResponse>
  </s:Body>
</s:Envelope>`))
		} else if strings.Contains(string(body), "Delete") || strings.Contains(string(body), "Signal") {
			// Delete/Signal response - empty body is fine
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body/>
</s:Envelope>`))
		}
	}))
	defer server.Close()
	// Extract host and port from server URL
	addr := strings.TrimPrefix(server.URL, "http://")
	client, err := NewClient(&Config{
		Host: strings.Split(addr, ":")[0],
		Port: 0, // Will be parsed from URL
		Auth: AuthBasic("user", "pass"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	// Override endpoint to use test server
	client.endpoint = server.URL
	// Test shell creation
	ctx := context.Background()
	envelope, _ := buildCreateShellEnvelope(client.endpoint, 153600, 60*time.Second)
	resp, err := client.send(ctx, envelope)
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}
	gotShellID, err := parseCreateShellResponse(resp)
	if err != nil {
		t.Fatalf("parseCreateShellResponse() error = %v", err)
	}
	if gotShellID != shellID {
		t.Errorf("expected shell ID %s, got %s", shellID, gotShellID)
	}
}
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Port != 5985 {
		t.Errorf("expected port 5985, got %d", config.Port)
	}
	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.ConnectTimeout)
	}
	if config.RetryConfig == nil {
		t.Error("expected retry config to be set")
	}
	if config.RetryConfig.MaxRetries != 3 {
		t.Errorf("expected 3 retries, got %d", config.RetryConfig.MaxRetries)
	}
}
func TestErrorTypes(t *testing.T) {
	// Test WinRMError
	winrmErr := &WinRMError{Code: "001", Message: "test error", Reason: "test reason"}
	if !strings.Contains(winrmErr.Error(), "001") {
		t.Error("error should contain code")
	}
	// Test SOAPFault
	soapFault := &SOAPFault{Code: "Sender", Reason: "bad request", Detail: "details"}
	if !strings.Contains(soapFault.Error(), "Sender") {
		t.Error("fault should contain code")
	}
	// Test PowerShellError
	psErr := &PowerShellError{Message: "script failed", ExitCode: 1, Stderr: "error output"}
	if !strings.Contains(psErr.Error(), "script failed") {
		t.Error("error should contain message")
	}
	// Test ParseError
	parseErr := &ParseError{Format: "JSON", Message: "invalid json"}
	if !strings.Contains(parseErr.Error(), "JSON") {
		t.Error("error should contain format")
	}
	// Test ErrInvalidConfig
	configErr := ErrInvalidConfig("missing host")
	if !strings.Contains(configErr.Error(), "missing host") {
		t.Error("error should contain message")
	}
}
func TestIsAuthError(t *testing.T) {
	if !IsAuthError(ErrAuthenticationFailed) {
		t.Error("should identify auth error")
	}
	if IsAuthError(ErrTimeout) {
		t.Error("should not identify timeout as auth error")
	}
}
func TestIsPowerShellError(t *testing.T) {
	psErr := &PowerShellError{Message: "test"}
	if !IsPowerShellError(psErr) {
		t.Error("should identify PowerShell error")
	}
	if IsPowerShellError(ErrTimeout) {
		t.Error("should not identify timeout as PowerShell error")
	}
}
func TestIsSOAPFault(t *testing.T) {
	fault := &SOAPFault{Code: "test"}
	if !IsSOAPFault(fault) {
		t.Error("should identify SOAP fault")
	}
	if IsSOAPFault(ErrTimeout) {
		t.Error("should not identify timeout as SOAP fault")
	}
}
