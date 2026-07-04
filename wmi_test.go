package winrm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestBuildWMIResourceURI(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{"forward slashes", "root/cimv2", wmiBaseURI + "/root/cimv2/*"},
		{"backslashes", `root\cimv2`, wmiBaseURI + "/root/cimv2/*"},
		{"dhcp namespace", WMINamespaceDHCP, wmiBaseURI + "/root/Microsoft/Windows/DHCP/*"},
		{"dhcp with backslashes", `root\Microsoft\Windows\DHCP`, wmiBaseURI + "/root/Microsoft/Windows/DHCP/*"},
		{"leading and trailing slashes", "/root/cimv2/", wmiBaseURI + "/root/cimv2/*"},
		{"empty defaults to cimv2", "", wmiBaseURI + "/root/cimv2/*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildWMIResourceURI(tt.namespace); got != tt.want {
				t.Errorf("buildWMIResourceURI(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestParseWMIEnumerateResponseProperties(t *testing.T) {
	// Response exercising array properties, xsi:nil, and nested CIM datetime.
	data := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common">
  <s:Body>
    <wsen:EnumerateResponse>
      <wsen:EnumerationContext></wsen:EnumerationContext>
      <w:Items>
        <p:Win32_NetworkAdapterConfiguration xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_NetworkAdapterConfiguration">
          <p:Description>Ethernet Adapter</p:Description>
          <p:IPAddress>192.168.1.10</p:IPAddress>
          <p:IPAddress>fe80::1</p:IPAddress>
          <p:DHCPServer xsi:nil="true"/>
          <p:DHCPLeaseObtained>
            <cim:Datetime>2026-07-01T10:00:00Z</cim:Datetime>
          </p:DHCPLeaseObtained>
          <p:IPEnabled>TRUE</p:IPEnabled>
          <p:Index>7</p:Index>
        </p:Win32_NetworkAdapterConfiguration>
      </w:Items>
      <wsen:EndOfSequence/>
    </wsen:EnumerateResponse>
  </s:Body>
</s:Envelope>`)

	enumCtx, items, err := parseWMIEnumerateResponse(data)
	if err != nil {
		t.Fatalf("parseWMIEnumerateResponse() error = %v", err)
	}
	if enumCtx != "" {
		t.Errorf("expected empty enum context on EndOfSequence, got %q", enumCtx)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(items))
	}

	inst := items[0]
	if inst.Class != "Win32_NetworkAdapterConfiguration" {
		t.Errorf("Class = %q", inst.Class)
	}
	if got := inst.GetString("Description"); got != "Ethernet Adapter" {
		t.Errorf("Description = %q", got)
	}

	// Array property must keep all elements.
	ips := inst.GetStrings("IPAddress")
	if len(ips) != 2 || ips[0] != "192.168.1.10" || ips[1] != "fe80::1" {
		t.Errorf("IPAddress = %v, want both values", ips)
	}

	// Null property must be omitted.
	if inst.Has("DHCPServer") {
		t.Errorf("expected xsi:nil property DHCPServer to be omitted")
	}
	if got := inst.GetString("DHCPServer"); got != "" {
		t.Errorf("GetString(nil prop) = %q, want empty", got)
	}

	// Nested cim:Datetime value must be resolved.
	if got := inst.GetString("DHCPLeaseObtained"); got != "2026-07-01T10:00:00Z" {
		t.Errorf("DHCPLeaseObtained = %q, want nested datetime value", got)
	}

	if b, err := inst.GetBool("IPEnabled"); err != nil || !b {
		t.Errorf("GetBool(IPEnabled) = %v, %v", b, err)
	}
	if n, err := inst.GetInt("Index"); err != nil || n != 7 {
		t.Errorf("GetInt(Index) = %d, %v", n, err)
	}
	if _, err := inst.GetInt("Missing"); err == nil {
		t.Errorf("GetInt(Missing) expected error")
	}
}

func TestParseWMIPullResponse(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Body>
    <wsen:PullResponse>
      <wsen:EnumerationContext>uuid:CTX-2</wsen:EnumerationContext>
      <wsen:Items>
        <p:Win32_Service xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service">
          <p:Name>Spooler</p:Name>
        </p:Win32_Service>
      </wsen:Items>
    </wsen:PullResponse>
  </s:Body>
</s:Envelope>`)

	enumCtx, items, err := parseWMIPullResponse(data)
	if err != nil {
		t.Fatalf("parseWMIPullResponse() error = %v", err)
	}
	if enumCtx != "uuid:CTX-2" {
		t.Errorf("enumCtx = %q, want uuid:CTX-2", enumCtx)
	}
	if len(items) != 1 || items[0].GetString("Name") != "Spooler" {
		t.Errorf("items = %+v", items)
	}
}

func newWMITestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	client, err := NewClient(&Config{
		Host: "localhost",
		Auth: AuthBasic("user", "pass"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.endpoint = serverURL
	return client
}

// TestWMIQueryEnumeratePullFlow exercises the full Enumerate → Pull → EndOfSequence flow.
func TestWMIQueryEnumeratePullFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		s := string(body)
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")

		switch {
		case strings.Contains(s, "enumeration/Enumerate<"):
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Body>
    <wsen:EnumerateResponse>
      <wsen:EnumerationContext>uuid:CTX-1</wsen:EnumerationContext>
      <w:Items>
        <p:DhcpServerv4Scope xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/Microsoft/Windows/DHCP/DhcpServerv4Scope">
          <p:ScopeId>10.0.0.0</p:ScopeId>
          <p:Name>LAN</p:Name>
        </p:DhcpServerv4Scope>
      </w:Items>
    </wsen:EnumerateResponse>
  </s:Body>
</s:Envelope>`))
		case strings.Contains(s, "enumeration/Pull<"):
			if !strings.Contains(s, "uuid:CTX-1") {
				t.Errorf("Pull request missing enumeration context, body: %s", s)
			}
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Body>
    <wsen:PullResponse>
      <wsen:Items>
        <p:DhcpServerv4Scope xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/Microsoft/Windows/DHCP/DhcpServerv4Scope">
          <p:ScopeId>10.0.1.0</p:ScopeId>
          <p:Name>GUEST</p:Name>
        </p:DhcpServerv4Scope>
      </wsen:Items>
      <wsen:EndOfSequence/>
    </wsen:PullResponse>
  </s:Body>
</s:Envelope>`))
		default:
			t.Errorf("unexpected request: %s", s)
		}
	}))
	defer server.Close()

	client := newWMITestClient(t, server.URL)
	items, err := client.WMIQuery(context.Background(), WMINamespaceDHCP, "SELECT * FROM DhcpServerv4Scope")
	if err != nil {
		t.Fatalf("WMIQuery() error = %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(items))
	}
	if items[0].GetString("ScopeId") != "10.0.0.0" || items[1].GetString("Name") != "GUEST" {
		t.Errorf("unexpected items: %+v", items)
	}
}

// TestWMIQueryReleasesContextOnPullFailure verifies that a failed Pull
// releases the original (still valid) enumeration context on the server.
func TestWMIQueryReleasesContextOnPullFailure(t *testing.T) {
	var mu sync.Mutex
	releasedCtx := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		s := string(body)
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")

		switch {
		case strings.Contains(s, "enumeration/Enumerate<"):
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Body>
    <wsen:EnumerateResponse>
      <wsen:EnumerationContext>uuid:CTX-LEAK</wsen:EnumerationContext>
    </wsen:EnumerateResponse>
  </s:Body>
</s:Envelope>`))
		case strings.Contains(s, "enumeration/Pull<"):
			// Non-temporary SOAP fault so the query fails immediately.
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>s:Receiver</s:Value></s:Code>
      <s:Reason><s:Text>boom</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`))
		case strings.Contains(s, "enumeration/Release<"):
			mu.Lock()
			if strings.Contains(s, "uuid:CTX-LEAK") {
				releasedCtx = "uuid:CTX-LEAK"
			}
			mu.Unlock()
			w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`))
		}
	}))
	defer server.Close()

	client := newWMITestClient(t, server.URL)
	_, err := client.WMIQuery(context.Background(), "root/cimv2", "SELECT * FROM Win32_Service")
	if err == nil {
		t.Fatal("expected WMIQuery to fail")
	}

	mu.Lock()
	defer mu.Unlock()
	if releasedCtx != "uuid:CTX-LEAK" {
		t.Errorf("enumeration context was not released with original context (got %q)", releasedCtx)
	}
}

// TestWMIGet exercises the Get path including selector round-trip.
func TestWMIGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		s := string(body)
		if !strings.Contains(s, `Name="Name"`) || !strings.Contains(s, ">Spooler<") {
			t.Errorf("Get request missing selector, body: %s", s)
		}
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <p:Win32_Service xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service">
      <p:Name>Spooler</p:Name>
      <p:State>Running</p:State>
    </p:Win32_Service>
  </s:Body>
</s:Envelope>`))
	}))
	defer server.Close()

	client := newWMITestClient(t, server.URL)
	inst, err := client.WMIGetDefault(context.Background(), "Win32_Service", map[string]string{"Name": "Spooler"})
	if err != nil {
		t.Fatalf("WMIGet() error = %v", err)
	}
	if inst.Class != "Win32_Service" || inst.GetString("State") != "Running" {
		t.Errorf("unexpected instance: %+v", inst)
	}
}
