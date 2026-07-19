package winrm

import (
	"net/http"
	"strings"
	"testing"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
)

// newTestKrbClient builds a gokrb5 client without logging in, so no TGT-renewal
// goroutine is started (Login is what starts it). This keeps the tests offline.
func newTestKrbClient() *krb5client.Client {
	cfg := krb5config.New()
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.COM"
	return krb5client.NewWithPassword("user", "EXAMPLE.COM", "pass", cfg)
}

// kerberosTransport.Close must Destroy the underlying gokrb5 client. gokrb5's
// Login starts a background TGT-renewal goroutine that only stops on Destroy, so
// failing to call it leaks a goroutine per connection.
func TestKerberosTransport_Close_DestroysClient(t *testing.T) {
	cl := newTestKrbClient()
	if got := cl.Credentials.UserName(); got != "user" {
		t.Fatalf("precondition: expected username %q, got %q", "user", got)
	}

	tr := &kerberosTransport{krbCl: cl}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if tr.krbCl != nil {
		t.Error("krbCl should be nil after Close")
	}
	if got := cl.Credentials.UserName(); got != "" {
		t.Errorf("Close must Destroy the client (clearing credentials); username still %q", got)
	}

	// Close must be safe to call again.
	if err := tr.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}

// Client.Close must reach the Kerberos transport (which implements io.Closer) so
// the gokrb5 client is destroyed when the WinRM client is closed.
func TestClient_Close_ClosesKerberosTransport(t *testing.T) {
	cl := newTestKrbClient()
	tr := &kerberosTransport{krbCl: cl}
	c := &Client{httpClient: &http.Client{Transport: tr}}

	if err := c.Close(); err != nil {
		t.Fatalf("Client.Close returned error: %v", err)
	}
	if tr.krbCl != nil {
		t.Error("Client.Close did not close the Kerberos transport (krbCl not cleared)")
	}
}

// When AuthConfig.KerberosConfig is set, getSPNEGOClient must use it directly and
// NOT read KerberosConfigFile. We point KerberosConfigFile at a bogus path: if the
// file were consulted the error would be "failed to load config"; instead it must
// get past config loading and fail at login (no KDC), proving in-memory precedence.
func TestGetSPNEGOClient_InMemoryConfigTakesPrecedence(t *testing.T) {
	cfg := krb5config.New()
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.COM"
	// No KDC and no DNS lookup, so Login fails fast and offline.

	tr := &kerberosTransport{
		config: &Config{
			Host: "winrm-host",
			Auth: AuthConfig{
				Type:               AuthTypeKerberos,
				Username:           "user",
				Password:           "pass",
				Domain:             "EXAMPLE.COM",
				KerberosConfig:     cfg,
				KerberosConfigFile: "/nonexistent/does-not-exist-krb5.conf",
			},
		},
	}

	_, err := tr.getSPNEGOClient()
	if err == nil {
		t.Fatal("expected an error (login should fail without a KDC)")
	}
	if strings.Contains(err.Error(), "failed to load config") {
		t.Errorf("in-memory config must take precedence over the file, but the file was read: %v", err)
	}
}
