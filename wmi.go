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
type WMIInstance struct {
	Class      string
	Properties map[string]string
}

// GetString returns a property value as string, or empty string if not found.
func (i *WMIInstance) GetString(name string) string {
	return i.Properties[name]
}

// GetInt returns a property value as int. Returns 0 and an error if not found or not parseable.
func (i *WMIInstance) GetInt(name string) (int, error) {
	s, ok := i.Properties[name]
	if !ok {
		return 0, fmt.Errorf("wmi: property %q not found", name)
	}
	return strconv.Atoi(s)
}

// GetBool returns a property value as bool ("True"/"False"). Returns false and an error if not found.
func (i *WMIInstance) GetBool(name string) (bool, error) {
	s, ok := i.Properties[name]
	if !ok {
		return false, fmt.Errorf("wmi: property %q not found", name)
	}
	return strings.EqualFold(s, "True"), nil
}

// GetUint64 returns a property value as uint64.
func (i *WMIInstance) GetUint64(name string) (uint64, error) {
	s, ok := i.Properties[name]
	if !ok {
		return 0, fmt.Errorf("wmi: property %q not found", name)
	}
	return strconv.ParseUint(s, 10, 64)
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
      <w:MaxElements>{{.MaxElements}}</w:MaxElements>
      <w:MaxTime>PT60S</w:MaxTime>
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
	XMLName xml.Name
	Value   string `xml:",chardata"`
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

	inst := &WMIInstance{
		Class:      instEl.XMLName.Local,
		Properties: make(map[string]string, len(instEl.Properties)),
	}
	for _, prop := range instEl.Properties {
		inst.Properties[prop.XMLName.Local] = prop.Value
	}

	return inst, nil
}

func convertItemsToInstances(items *wmiItemsEl) []WMIInstance {
	instances := make([]WMIInstance, 0, len(items.Instances))
	for _, raw := range items.Instances {
		inst := WMIInstance{
			Class:      raw.XMLName.Local,
			Properties: make(map[string]string, len(raw.Properties)),
		}
		for _, prop := range raw.Properties {
			inst.Properties[prop.XMLName.Local] = prop.Value
		}
		instances = append(instances, inst)
	}
	return instances
}

// ---- Client methods ----

// WMIQuery executes a WQL query against the specified WMI namespace.
// This is a low-privilege operation that does not create a shell or process
// on the remote host — it uses WS-Management's enumeration protocol directly.
func (c *Client) WMIQuery(ctx context.Context, namespace, wql string) ([]WMIInstance, error) {
	resourceURI := buildWMIResourceURI(namespace)
	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIEnumerateEnvelope(c.endpoint, resourceURI, wql, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return nil, err
	}

	resp, err := c.send(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("wmi query failed: %w", err)
	}

	enumCtx, items, err := parseWMIEnumerateResponse(resp)
	if err != nil {
		return nil, err
	}

	for enumCtx != "" {
		enumCtx, more, err := c.wmiPull(ctx, resourceURI, enumCtx)
		if err != nil {
			c.wmiRelease(ctx, resourceURI, enumCtx)
			return nil, err
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

	resp, err := c.send(ctx, envelope)
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

	resp, err := c.send(ctx, envelope)
	if err != nil {
		return "", nil, fmt.Errorf("wmi pull failed: %w", err)
	}

	return parseWMIPullResponse(resp)
}

func (c *Client) wmiRelease(ctx context.Context, resourceURI, enumContext string) {
	if enumContext == "" {
		return
	}

	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIReleaseEnvelope(c.endpoint, resourceURI, enumContext, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return
	}

	releaseCtx, cancel := context.WithTimeout(ctx, c.config.SendTimeout)
	defer cancel()

	_, _ = c.send(releaseCtx, envelope)
}

// buildWMIResourceURI builds the WS-Management resource URI for a WMI namespace.
// For example, "root/cimv2" becomes "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*".
func buildWMIResourceURI(namespace string) string {
	ns := strings.Trim(namespace, "/")
	if ns == "" {
		ns = WMINamespaceRootCIMV2
	}
	return wmiBaseURI + "/" + ns + "/*"
}

func newWmiMessageID() string {
	return "uuid:" + uuid.New().String()
}
