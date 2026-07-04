package winrm

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

// WMI custom method invocation (WS-Management Invoke).
//
// CDXML-based WMI providers (e.g. the DHCP Server provider in
// root/Microsoft/Windows/DHCP) expose method-only classes such as
// PS_DhcpServerv4Scope: their data cannot be enumerated with WQL, it must be
// retrieved by invoking a static CIM method like Get. This file implements
// that Invoke operation on top of the same transport as the other WMI calls.

// WMIParam is a single input parameter for a WMI method invocation.
// Repeat the same Name for array-valued parameters.
type WMIParam struct {
	Name  string
	Value string
}

// WMIMethodResult is the parsed result of a WMI method invocation.
type WMIMethodResult struct {
	// ReturnValue is the method's ReturnValue output parameter as a string
	// ("0" typically means success).
	ReturnValue string
	// Out contains scalar output parameters (excluding ReturnValue).
	Out map[string][]string
	// Instances contains embedded CIM instances returned in output
	// parameters (e.g. the cmdletOutput array of CDXML Get methods).
	Instances []WMIInstance
}

// xmlNameRe restricts class, method and parameter names to safe XML NCName
// characters, since they are interpolated into XML element names and URIs.
var xmlNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

type wmiInvokeParams struct {
	MessageID        string
	ResourceURI      string
	ActionURI        string
	Endpoint         string
	OperationTimeout string
	MaxEnvelopeSize  int
	Method           string
	Params           []WMIParam
	Namespaces       string
}

var wmiInvokeTemplate = template.Must(template.New("wmiInvoke").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <a:Action s:mustUnderstand="true">{{.ActionURI}}</a:Action>
  </s:Header>
  <s:Body>
    <i:{{.Method}}_INPUT xmlns:i="{{.ResourceURI}}">{{range .Params}}
      <i:{{.Name}}>{{.Value}}</i:{{.Name}}>{{end}}
    </i:{{.Method}}_INPUT>
  </s:Body>
</s:Envelope>`))

// buildWMIClassResourceURI builds the resource URI for a specific WMI class
// (no trailing /*, unlike enumeration which targets the whole namespace).
func buildWMIClassResourceURI(namespace, className string) string {
	ns := strings.ReplaceAll(namespace, "\\", "/")
	ns = strings.Trim(ns, "/")
	if ns == "" {
		ns = WMINamespaceRootCIMV2
	}
	return wmiBaseURI + "/" + ns + "/" + className
}

func buildWMIInvokeEnvelope(endpoint, namespace, className, method string, params []WMIParam, maxEnvelopeSize int, operationTimeout string) ([]byte, error) {
	if !xmlNameRe.MatchString(className) {
		return nil, fmt.Errorf("wmi: invalid class name %q", className)
	}
	if !xmlNameRe.MatchString(method) {
		return nil, fmt.Errorf("wmi: invalid method name %q", method)
	}

	escaped := make([]WMIParam, 0, len(params))
	for _, p := range params {
		if !xmlNameRe.MatchString(p.Name) {
			return nil, fmt.Errorf("wmi: invalid parameter name %q", p.Name)
		}
		escaped = append(escaped, WMIParam{Name: p.Name, Value: escapeXML(p.Value)})
	}

	resourceURI := buildWMIClassResourceURI(namespace, className)
	data := wmiInvokeParams{
		MessageID:        newWmiMessageID(),
		ResourceURI:      resourceURI,
		ActionURI:        resourceURI + "/" + method,
		Endpoint:         escapeXML(endpoint),
		OperationTimeout: operationTimeout,
		MaxEnvelopeSize:  maxEnvelopeSize,
		Method:           method,
		Params:           escaped,
		Namespaces:       wmiXMLNamespaces,
	}

	var buf bytes.Buffer
	if err := wmiInvokeTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build wmi invoke envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- Response parsing ----

type wmiInvokeEnvelope struct {
	XMLName xml.Name          `xml:"Envelope"`
	Body    wmiInvokeSoapBody `xml:"Body"`
}

type wmiInvokeSoapBody struct {
	Fault  *soapFaultResponse `xml:"Fault"`
	Output *wmiInstanceEl     `xml:",any"`
}

// parseWMIInvokeResponse parses a <Method>_OUTPUT response body.
func parseWMIInvokeResponse(data []byte) (*WMIMethodResult, error) {
	var envelope wmiInvokeEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse wmi invoke response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return nil, parseFault(envelope.Body.Fault)
	}

	out := envelope.Body.Output
	if out == nil || !strings.HasSuffix(out.XMLName.Local, "_OUTPUT") {
		return nil, fmt.Errorf("wmi: missing method output in invoke response body")
	}

	result := &WMIMethodResult{Out: make(map[string][]string)}
	for _, p := range out.Properties {
		switch {
		case p.XMLName.Local == "ReturnValue":
			v, _ := p.resolveValue()
			result.ReturnValue = v
		case len(p.Children) == 0:
			if v, ok := p.resolveValue(); ok {
				result.Out[p.XMLName.Local] = append(result.Out[p.XMLName.Local], v)
			}
		case p.Type != "" || !allChildrenNested(p):
			// Flat embedded instance: <cmdletOutput xsi:type="p1:DhcpServerv4Scope">
			// with property elements as direct children.
			result.Instances = append(result.Instances, instanceFromProperty(p))
		default:
			// Wrapper element: each child is an embedded instance,
			// e.g. <cmdletOutput><DhcpServerv4Scope>...</DhcpServerv4Scope></cmdletOutput>.
			for _, ch := range p.Children {
				result.Instances = append(result.Instances, instanceFromProperty(ch))
			}
		}
	}

	return result, nil
}

// allChildrenNested reports whether every child element itself has children,
// which indicates a wrapper around embedded instances rather than a flat
// instance whose properties may contain nested values (e.g. cim:Datetime).
func allChildrenNested(p wmiPropertyEl) bool {
	for _, ch := range p.Children {
		if len(ch.Children) == 0 {
			return false
		}
	}
	return len(p.Children) > 0
}

// instanceFromProperty converts an embedded-instance XML element into a
// WMIInstance. The class name comes from the xsi:type attribute when present
// (e.g. "p1:DhcpServerv4Scope"), otherwise from the element name.
func instanceFromProperty(p wmiPropertyEl) WMIInstance {
	class := p.XMLName.Local
	if p.Type != "" {
		if idx := strings.LastIndex(p.Type, ":"); idx >= 0 {
			class = p.Type[idx+1:]
		} else {
			class = p.Type
		}
	}

	inst := WMIInstance{
		Class:      class,
		Properties: make(map[string][]string, len(p.Children)),
	}
	for _, ch := range p.Children {
		v, ok := ch.resolveValue()
		if !ok {
			continue
		}
		name := ch.XMLName.Local
		inst.Properties[name] = append(inst.Properties[name], v)
	}
	return inst
}

// ---- Client methods ----

// WMIInvoke invokes a (static) CIM method on a WMI class via WS-Management,
// without creating a shell or process on the remote host. Use it for CDXML
// method-only classes such as PS_DhcpServerv4Scope in the DHCP namespace.
//
// The request is NOT retried, because arbitrary methods may not be
// idempotent. For read-only Get-style methods use WMIInvokeGet, which
// retries transient failures.
func (c *Client) WMIInvoke(ctx context.Context, namespace, className, method string, params []WMIParam) (*WMIMethodResult, error) {
	return c.wmiInvoke(ctx, namespace, className, method, params, false)
}

// WMIInvokeGet invokes a read-only (idempotent) CIM method such as the
// CDXML "Get" method, retrying transient failures with the client's
// retry policy. Do not use it for methods with side effects.
func (c *Client) WMIInvokeGet(ctx context.Context, namespace, className, method string, params []WMIParam) (*WMIMethodResult, error) {
	return c.wmiInvoke(ctx, namespace, className, method, params, true)
}

func (c *Client) wmiInvoke(ctx context.Context, namespace, className, method string, params []WMIParam, retry bool) (*WMIMethodResult, error) {
	operationTimeout := formatTimeout(c.config.OperationTimeout)

	envelope, err := buildWMIInvokeEnvelope(c.endpoint, namespace, className, method, params, c.config.MaxEnvelopeSize, operationTimeout)
	if err != nil {
		return nil, err
	}

	var resp []byte
	if retry {
		resp, err = c.sendWithRetry(ctx, envelope)
	} else {
		resp, err = c.send(ctx, envelope)
	}
	if err != nil {
		return nil, fmt.Errorf("wmi invoke %s.%s failed: %w", className, method, err)
	}

	return parseWMIInvokeResponse(resp)
}
