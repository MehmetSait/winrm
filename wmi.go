package winrm

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/uuid"
)

// WMI-specific WS-Management constants.
const (
	wmiBaseURI = "http://schemas.microsoft.com/wbem/wsman/1/wmi"

	wmiEnumerateAction = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	wmiPullAction      = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
	wmiReleaseAction   = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release"
	wmiGetAction       = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"

	wmiFilterDialectWQL = "http://schemas.microsoft.com/wbem/wsman/1/WQL"

	// WMINamespaceRootCIMV2 is the default WMI namespace root\cimv2.
	WMINamespaceRootCIMV2 = "root/cimv2"

	// WMINamespaceDHCP is the Microsoft DHCP Server WMI namespace
	// (root\Microsoft\Windows\DHCP, Windows Server 2012+). The PS_* classes
	// in it are CDXML method-only classes: they are NOT enumerable via
	// WMIQuery/WMIEnumerate — use WMIInvoke (or the DHCP helpers) instead.
	WMINamespaceDHCP = "root/Microsoft/Windows/DHCP"

	// WMINamespaceLegacyDHCP is the legacy DHCP WMI namespace with
	// enumerable classes (Microsoft_DHCP_Scope, Microsoft_DHCP_Client, ...).
	// It may not be registered on Windows Server 2012+.
	WMINamespaceLegacyDHCP = "root/MicrosoftDHCP"
)

// WMI-specific XML namespaces (replaces shell-specific rsp with wsen and wxf).
const wmiXMLNamespaces = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
	`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" ` +
	`xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" ` +
	`xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" ` +
	`xmlns:wxf="http://schemas.xmlsoap.org/ws/2004/09/transfer" ` +
	`xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"`

// wmiEnvelopeParams holds parameters for WMI SOAP envelopes.
type wmiEnvelopeParams struct {
	MessageID        string
	Action           string
	ResourceURI      string
	Endpoint         string
	OperationTimeout string
	MaxEnvelopeSize  int
	EnumContext      string
	FilterDialect    string
	FilterText       string
	MaxElements      int
	Selectors        []wmiSelector
}

type wmiSelector struct {
	Name  string
	Value string
}

// WMIInstance represents a single WMI/CIM instance with its properties.
// Array-valued properties (e.g. IPAddress) keep all their elements.
// Properties whose value is null (xsi:nil="true") are omitted from the map,
// so "not present" means the server reported the property as null.
type WMIInstance struct {
	Class      string
	Properties map[string][]string
}

// GetString returns the first value of a property as string,
// or empty string if the property is not present.
func (i *WMIInstance) GetString(name string) string {
	if vals := i.Properties[name]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// GetStrings returns all values of an array-valued property,
// or nil if the property is not present.
func (i *WMIInstance) GetStrings(name string) []string {
	return i.Properties[name]
}

// Has reports whether the property is present (i.e. was returned by the
// server with a non-null value).
func (i *WMIInstance) Has(name string) bool {
	_, ok := i.Properties[name]
	return ok
}

// GetInt returns a property value as int. Returns 0 and an error if not found or not parseable.
func (i *WMIInstance) GetInt(name string) (int, error) {
	vals, ok := i.Properties[name]
	if !ok || len(vals) == 0 {
		return 0, fmt.Errorf("wmi: property %q not found", name)
	}
	return strconv.Atoi(vals[0])
}

// GetBool returns a property value as bool ("True"/"False"). Returns false and an error if not found.
func (i *WMIInstance) GetBool(name string) (bool, error) {
	vals, ok := i.Properties[name]
	if !ok || len(vals) == 0 {
		return false, fmt.Errorf("wmi: property %q not found", name)
	}
	return strings.EqualFold(vals[0], "True"), nil
}

// GetUint64 returns a property value as uint64.
func (i *WMIInstance) GetUint64(name string) (uint64, error) {
	vals, ok := i.Properties[name]
	if !ok || len(vals) == 0 {
		return 0, fmt.Errorf("wmi: property %q not found", name)
	}
	return strconv.ParseUint(vals[0], 10, 64)
}

// wmiTemplateData wraps WMI envelope params with namespaces.
type wmiTemplateData struct {
	wmiEnvelopeParams
	Namespaces string
}

// ---- SOAP envelope templates ----

var wmiEnumerateTemplate = template.Must(template.New("wmiEnumerate").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope {{.Namespaces}}>
  <s:Header>
    <a:To>{{.Endpoint}}</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:MaxEnvelopeSize s:mustUnderstand="true">{{.MaxEnvelopeSize}}</w:MaxEnvelopeSize>
    <a:MessageID>{{.MessageID}}</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>{{.OperationTimeout}}</w:OperationTimeout>
    <w:ResourceURI s:mustUnderstand="true">{{.ResourceURI}}</w:ResourceURI>
    <a:Action s:mustUnderstand="true">{{.Action}}</a:Action>
  </s:Header>
  <s:Body>
    <wsen:Enumerate>
      <w:OptimizeEnumeration>true</w:OptimizeEnumeration>
      <w:MaxElements>{{.MaxElements}}</w:MaxElements>{{if .FilterDialect}}
      <w:Filter Dialect="{{.FilterDialect}}">{{.FilterText}}</w:Filter>{{end}}
    </wsen:Enumerate>
  </s:Body>
</s:Envelope>`))

var wmiPullTemplate = template.Must(template.New("wmiPull").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope {{.Namespaces}}>
  <s:Header>
    <a:To>{{.Endpoint}}</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:MaxEnvelopeSize s:mustUnderstand="true">{{.MaxEnvelopeSize}}</w:MaxEnvelopeSize>
    <a:MessageID>{{.MessageID}}</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>{{.OperationTimeout}}</w:OperationTimeout>
    <w:ResourceURI s:mustUnderstand="true">{{.ResourceURI}}</w:ResourceURI>
    <a:Action s:mustUnderstand="true">{{.Action}}</a:Action>
  </s:Header>
  <s:Body>
    <wsen:Pull>
      <wsen:EnumerationContext>{{.EnumContext}}</wsen:EnumerationContext>
      <wsen:MaxElements>{{.MaxElements}}</wsen:MaxElements>
    </wsen:Pull>
  </s:Body>
</s:Envelope>`))

var wmiReleaseTemplate = template.Must(template.New("wmiRelease").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope {{.Namespaces}}>
  <s:Header>
    <a:To>{{.Endpoint}}</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:MaxEnvelopeSize s:mustUnderstand="true">{{.MaxEnvelopeSize}}</w:MaxEnvelopeSize>
    <a:MessageID>{{.MessageID}}</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>{{.OperationTimeout}}</w:OperationTimeout>
    <w:ResourceURI s:mustUnderstand="true">{{.ResourceURI}}</w:ResourceURI>
    <a:Action s:mustUnderstand="true">{{.Action}}</a:Action>
  </s:Header>
  <s:Body>
    <wsen:Release>
      <wsen:EnumerationContext>{{.EnumContext}}</wsen:EnumerationContext>
    </wsen:Release>
  </s:Body>
</s:Envelope>`))

var wmiGetTemplate = template.Must(template.New("wmiGet").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope {{.Namespaces}}>
  <s:Header>
    <a:To>{{.Endpoint}}</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:MaxEnvelopeSize s:mustUnderstand="true">{{.MaxEnvelopeSize}}</w:MaxEnvelopeSize>
    <a:MessageID>{{.MessageID}}</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>{{.OperationTimeout}}</w:OperationTimeout>
    <w:ResourceURI s:mustUnderstand="true">{{.ResourceURI}}</w:ResourceURI>
    <a:Action s:mustUnderstand="true">{{.Action}}</a:Action>{{if .Selectors}}
    <w:SelectorSet>{{range .Selectors}}
      <w:Selector Name="{{.Name}}">{{.Value}}</w:Selector>{{end}}
    </w:SelectorSet>{{end}}
  </s:Header>
  <s:Body/>
</s:Envelope>`))

// ---- Builder functions ----

func buildWMIEnumerateEnvelope(endpoint, resourceURI, wqlFilter string, maxEnvelopeSize int, operationTimeout string) ([]byte, error) {
	data := wmiTemplateData{
		wmiEnvelopeParams: wmiEnvelopeParams{
			MessageID:        newWmiMessageID(),
			Action:           wmiEnumerateAction,
			ResourceURI:      resourceURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: operationTimeout,
			MaxEnvelopeSize:  maxEnvelopeSize,
			MaxElements:      100,
			FilterDialect:    wmiFilterDialectWQL,
			FilterText:       escapeXML(wqlFilter),
		},
		Namespaces: wmiXMLNamespaces,
	}

	var buf bytes.Buffer
	if err := wmiEnumerateTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build wmi enumerate envelope: %w", err)
	}
	return buf.Bytes(), nil
}

func buildWMIPullEnvelope(endpoint, resourceURI, enumContext string, maxEnvelopeSize int, operationTimeout string) ([]byte, error) {
	data := wmiTemplateData{
		wmiEnvelopeParams: wmiEnvelopeParams{
			MessageID:        newWmiMessageID(),
			Action:           wmiPullAction,
			ResourceURI:      resourceURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: operationTimeout,
			MaxEnvelopeSize:  maxEnvelopeSize,
			EnumContext:      escapeXML(enumContext),
			MaxElements:      100,
		},
		Namespaces: wmiXMLNamespaces,
	}

	var buf bytes.Buffer
	if err := wmiPullTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build wmi pull envelope: %w", err)
	}
	return buf.Bytes(), nil
}

func buildWMIReleaseEnvelope(endpoint, resourceURI, enumContext string, maxEnvelopeSize int, operationTimeout string) ([]byte, error) {
	data := wmiTemplateData{
		wmiEnvelopeParams: wmiEnvelopeParams{
			MessageID:        newWmiMessageID(),
			Action:           wmiReleaseAction,
			ResourceURI:      resourceURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: operationTimeout,
			MaxEnvelopeSize:  maxEnvelopeSize,
			EnumContext:      escapeXML(enumContext),
		},
		Namespaces: wmiXMLNamespaces,
	}

	var buf bytes.Buffer
	if err := wmiReleaseTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build wmi release envelope: %w", err)
	}
	return buf.Bytes(), nil
}

func buildWMIGetEnvelope(endpoint, resourceURI string, selectors []wmiSelector, maxEnvelopeSize int, operationTimeout string) ([]byte, error) {
	data := wmiTemplateData{
		wmiEnvelopeParams: wmiEnvelopeParams{
			MessageID:        newWmiMessageID(),
			Action:           wmiGetAction,
			ResourceURI:      resourceURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: operationTimeout,
			MaxEnvelopeSize:  maxEnvelopeSize,
			Selectors:        selectors,
		},
		Namespaces: wmiXMLNamespaces,
	}

	var buf bytes.Buffer
	if err := wmiGetTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build wmi get envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- SOAP response structures ----

// wmiSoapEnvelope is a SOAP envelope for WMI responses.
type wmiSoapEnvelope struct {
	XMLName xml.Name      `xml:"Envelope"`
	Header  wmiSoapHeader `xml:"Header"`
	Body    wmiSoapBody   `xml:"Body"`
}

type wmiSoapHeader struct {
	Action string `xml:"Action"`
}

type wmiSoapBody struct {
	EnumerateResponse *wmiEnumerateResponseEl `xml:"EnumerateResponse"`
	PullResponse      *wmiPullResponseEl      `xml:"PullResponse"`
	Items             *wmiItemsEl             `xml:"Items"`
	Instance          *wmiInstanceEl          `xml:",any"`
	Fault             *soapFaultResponse      `xml:"Fault"`
}

type wmiEnumerateResponseEl struct {
	EnumerationContext string      `xml:"EnumerationContext"`
	Items              *wmiItemsEl `xml:"Items"`
	EndOfSequence      *endOfSeqEl `xml:"EndOfSequence"`
}

type wmiPullResponseEl struct {
	EnumerationContext string      `xml:"EnumerationContext"`
	Items              *wmiItemsEl `xml:"Items"`
	EndOfSequence      *endOfSeqEl `xml:"EndOfSequence"`
}

type endOfSeqEl struct{}

type wmiItemsEl struct {
	Instances []wmiInstanceEl `xml:",any"`
}

type wmiInstanceEl struct {
	XMLName    xml.Name
	Properties []wmiPropertyEl `xml:",any"`
}

type wmiPropertyEl struct {
	XMLName  xml.Name
	Nil      string          `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
	Type     string          `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value    string          `xml:",chardata"`
	Children []wmiPropertyEl `xml:",any"`
}

// resolveValue returns the property's text value, descending into nested
// elements such as <cim:Datetime>. ok is false when the property is
// null (xsi:nil="true").
func (p *wmiPropertyEl) resolveValue() (value string, ok bool) {
	if p.Nil == "true" || p.Nil == "1" {
		return "", false
	}
	v := strings.TrimSpace(p.Value)
	if v == "" && len(p.Children) > 0 {
		return p.Children[0].resolveValue()
	}
	return v, true
}

// ---- Response parsers ----

// parseWMIEnumerateResponse parses an Enumerate response, returning
// the enumeration context and any items returned in the first batch.
func parseWMIEnumerateResponse(data []byte) (enumContext string, items []WMIInstance, err error) {
	var envelope wmiSoapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return "", nil, fmt.Errorf("failed to parse wmi enumerate response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return "", nil, parseFault(envelope.Body.Fault)
	}

	resp := envelope.Body.EnumerateResponse
	if resp == nil {
		return "", nil, fmt.Errorf("wmi: missing EnumerateResponse in SOAP body")
	}

	if resp.Items != nil {
		items = convertItemsToInstances(resp.Items)
	}

	if resp.EndOfSequence == nil {
		enumContext = resp.EnumerationContext
	}

	return enumContext, items, nil
}

// parseWMIPullResponse parses a Pull response.
func parseWMIPullResponse(data []byte) (enumContext string, items []WMIInstance, err error) {
	var envelope wmiSoapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return "", nil, fmt.Errorf("failed to parse wmi pull response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return "", nil, parseFault(envelope.Body.Fault)
	}

	resp := envelope.Body.PullResponse
	if resp == nil {
		return "", nil, fmt.Errorf("wmi: missing PullResponse in SOAP body")
	}

	if resp.Items != nil {
		items = convertItemsToInstances(resp.Items)
	}

	if resp.EndOfSequence == nil {
		enumContext = resp.EnumerationContext
	}

	return enumContext, items, nil
}

// parseWMIGetResponse parses a Get response, returning the single instance.
func parseWMIGetResponse(data []byte) (*WMIInstance, error) {
	var envelope wmiSoapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse wmi get response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return nil, parseFault(envelope.Body.Fault)
	}

	instEl := envelope.Body.Instance
	if instEl == nil {
		return nil, fmt.Errorf("wmi: missing instance in Get response body")
	}

	inst := convertInstanceEl(instEl)
	return &inst, nil
}

func convertItemsToInstances(items *wmiItemsEl) []WMIInstance {
	instances := make([]WMIInstance, 0, len(items.Instances))
	for _, raw := range items.Instances {
		instances = append(instances, convertInstanceEl(&raw))
	}
	return instances
}

// convertInstanceEl converts a raw XML instance element into a WMIInstance,
// collecting array-valued properties and skipping null (xsi:nil) properties.
func convertInstanceEl(el *wmiInstanceEl) WMIInstance {
	inst := WMIInstance{
		Class:      el.XMLName.Local,
		Properties: make(map[string][]string, len(el.Properties)),
	}
	for _, prop := range el.Properties {
		v, ok := prop.resolveValue()
		if !ok {
			continue
		}
		name := prop.XMLName.Local
		inst.Properties[name] = append(inst.Properties[name], v)
	}
	return inst
}

// ---- Client methods ----

// WMIQuery executes a WQL query against the specified WMI namespace.
// This is a low-privilege operation that does not create a shell or process
// on the remote host — it uses WS-Management's enumeration protocol directly.
//
// The query text is XML-escaped, but no WQL-level escaping is performed:
// when building queries from untrusted input, sanitize values yourself
// (WQL string literals escape ' by doubling it).
func (c *Client) WMIQuery(ctx context.Context, namespace, wql string) ([]WMIInstance, error) {
	resourceURI := buildWMIResourceURI(namespace)
	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIEnumerateEnvelope(c.endpoint, resourceURI, wql, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return nil, err
	}

	// Enumerate is idempotent, so transient failures can be retried safely.
	resp, err := c.sendWithRetry(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("wmi query failed: %w", err)
	}

	enumCtx, items, err := parseWMIEnumerateResponse(resp)
	if err != nil {
		return nil, err
	}

	for enumCtx != "" {
		prevCtx := enumCtx
		var more []WMIInstance
		var pullErr error
		enumCtx, more, pullErr = c.wmiPull(ctx, resourceURI, prevCtx)
		if pullErr != nil {
			// Release the still-open enumeration context so it does not
			// leak on the server (they count against WinRM quotas).
			c.wmiRelease(resourceURI, prevCtx)
			return nil, pullErr
		}
		items = append(items, more...)
	}

	return items, nil
}

// WMIQueryDefault executes a WQL query against root\cimv2.
func (c *Client) WMIQueryDefault(ctx context.Context, wql string) ([]WMIInstance, error) {
	return c.WMIQuery(ctx, WMINamespaceRootCIMV2, wql)
}

// WMIEnumerate enumerates all instances of a WMI class in the given namespace.
func (c *Client) WMIEnumerate(ctx context.Context, namespace, className string) ([]WMIInstance, error) {
	wql := "SELECT * FROM " + className
	return c.WMIQuery(ctx, namespace, wql)
}

// WMIEnumerateDefault enumerates all instances of a WMI class from root\cimv2.
func (c *Client) WMIEnumerateDefault(ctx context.Context, className string) ([]WMIInstance, error) {
	return c.WMIEnumerate(ctx, WMINamespaceRootCIMV2, className)
}

// WMIGet retrieves a single WMI instance by its key properties.
// The keys map should contain the key property name(s) and their values
// (e.g., map[string]string{"Name": "Spooler"} for Win32_Service).
func (c *Client) WMIGet(ctx context.Context, namespace, className string, keys map[string]string) (*WMIInstance, error) {
	resourceURI := buildWMIResourceURI(namespace)
	operationTimeout := formatTimeout(c.config.OperationTimeout)

	selectors := make([]wmiSelector, 0, len(keys))
	for name, value := range keys {
		selectors = append(selectors, wmiSelector{
			Name:  escapeXML(name),
			Value: escapeXML(value),
		})
	}

	envelope, err := buildWMIGetEnvelope(c.endpoint, resourceURI, selectors, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return nil, err
	}

	// Get is idempotent, so transient failures can be retried safely.
	resp, err := c.sendWithRetry(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("wmi get failed: %w", err)
	}

	return parseWMIGetResponse(resp)
}

// WMIGetDefault retrieves a single WMI instance from root\cimv2 by key properties.
func (c *Client) WMIGetDefault(ctx context.Context, className string, keys map[string]string) (*WMIInstance, error) {
	return c.WMIGet(ctx, WMINamespaceRootCIMV2, className, keys)
}

// ---- Internal helpers ----

func (c *Client) wmiPull(ctx context.Context, resourceURI, enumContext string) (newContext string, items []WMIInstance, err error) {
	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIPullEnvelope(c.endpoint, resourceURI, enumContext, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return "", nil, err
	}

	// Pull is intentionally NOT retried: a Pull that succeeded server-side
	// but whose response was lost advances the cursor, so retrying could
	// silently skip items.
	resp, err := c.send(ctx, envelope)
	if err != nil {
		return "", nil, fmt.Errorf("wmi pull failed: %w", err)
	}

	return parseWMIPullResponse(resp)
}

// wmiRelease releases an enumeration context on the server (best effort).
// It deliberately uses a fresh context: the caller's context is typically
// already canceled or timed out when cleanup runs, and skipping Release
// would leak the enumeration against WinRM server quotas.
func (c *Client) wmiRelease(resourceURI, enumContext string) {
	if enumContext == "" {
		return
	}

	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIReleaseEnvelope(c.endpoint, resourceURI, enumContext, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return
	}

	releaseCtx, cancel := context.WithTimeout(context.Background(), c.config.SendTimeout)
	defer cancel()

	_, _ = c.send(releaseCtx, envelope)
}

// buildWMIResourceURI builds the WS-Management resource URI for a WMI namespace.
// Both "root/cimv2" and the classic "root\cimv2" notations are accepted.
// For example, "root/cimv2" becomes "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*".
func buildWMIResourceURI(namespace string) string {
	ns := strings.ReplaceAll(namespace, "\\", "/")
	ns = strings.Trim(ns, "/")
	if ns == "" {
		ns = WMINamespaceRootCIMV2
	}
	return wmiBaseURI + "/" + ns + "/*"
}

func newWmiMessageID() string {
	return "uuid:" + uuid.New().String()
}
