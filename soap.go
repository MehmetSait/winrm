package winrm

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
)

// SOAP envelope templates for WinRM operations.

const (
	xmlNamespaces = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" ` +
		`xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" ` +
		`xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" ` +
		`xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"`

	shellURI   = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	commandURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	receiveURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	signalURI  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
	sendURI    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
	deleteURI  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	createURI  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
)

// envelopeParams holds parameters for generating SOAP envelopes.
type envelopeParams struct {
	MessageID        string
	Action           string
	ResourceURI      string
	Endpoint         string
	OperationTimeout string
	MaxEnvelopeSize  int
	ShellID          string
	CommandID        string
	Command          string
	Arguments        string
	Codepage         string
	Signal           string
}

// newMessageID generates a new UUID for SOAP messages.
func newMessageID() string {
	return "uuid:" + uuid.New().String()
}

// formatTimeout formats a duration as an ISO 8601 duration string.
func formatTimeout(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("PT%dS", secs)
	}
	mins := secs / 60
	secs = secs % 60
	if secs == 0 {
		return fmt.Sprintf("PT%dM", mins)
	}
	return fmt.Sprintf("PT%dM%dS", mins, secs)
}

// createShellEnvelope creates a SOAP envelope for creating a new shell.
var createShellTemplate = template.Must(template.New("createShell").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:OptionSet>
      <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
      <w:Option Name="WINRS_CODEPAGE">{{.Codepage}}</w:Option>
    </w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>`))

// executeCommandTemplate creates a SOAP envelope for executing a command.
var executeCommandTemplate = template.Must(template.New("executeCommand").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:SelectorSet>
      <w:Selector Name="ShellId">{{.ShellID}}</w:Selector>
    </w:SelectorSet>
    <w:OptionSet>
      <w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option>
      <w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option>
    </w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{{.Command}}</rsp:Command>
      <rsp:Arguments>{{.Arguments}}</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>`))

// receiveOutputTemplate creates a SOAP envelope for receiving command output.
var receiveOutputTemplate = template.Must(template.New("receiveOutput").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:SelectorSet>
      <w:Selector Name="ShellId">{{.ShellID}}</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{{.CommandID}}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>`))

// signalTemplate creates a SOAP envelope for sending a signal to a command.
var signalTemplate = template.Must(template.New("signal").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:SelectorSet>
      <w:Selector Name="ShellId">{{.ShellID}}</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Signal CommandId="{{.CommandID}}">
      <rsp:Code>{{.Signal}}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>`))

// deleteShellTemplate creates a SOAP envelope for deleting a shell.
var deleteShellTemplate = template.Must(template.New("deleteShell").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:SelectorSet>
      <w:Selector Name="ShellId">{{.ShellID}}</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>`))

// templateData wraps envelope params with additional fields.
type templateData struct {
	envelopeParams
	Namespaces string
}

// buildCreateShellEnvelope builds the SOAP envelope for creating a shell.
func buildCreateShellEnvelope(endpoint string, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	data := templateData{
		envelopeParams: envelopeParams{
			MessageID:        newMessageID(),
			Action:           createURI,
			ResourceURI:      shellURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: formatTimeout(operationTimeout),
			MaxEnvelopeSize:  maxEnvelopeSize,
			Codepage:         "65001", // UTF-8
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := createShellTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build create shell envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// buildExecuteCommandEnvelope builds the SOAP envelope for executing a command.
func buildExecuteCommandEnvelope(endpoint, shellID, command, arguments string, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	data := templateData{
		envelopeParams: envelopeParams{
			MessageID:        newMessageID(),
			Action:           commandURI,
			ResourceURI:      shellURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: formatTimeout(operationTimeout),
			MaxEnvelopeSize:  maxEnvelopeSize,
			ShellID:          escapeXML(shellID),
			Command:          escapeXML(command),
			Arguments:        escapeXML(arguments),
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := executeCommandTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build execute command envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// buildReceiveOutputEnvelope builds the SOAP envelope for receiving output.
func buildReceiveOutputEnvelope(endpoint, shellID, commandID string, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	data := templateData{
		envelopeParams: envelopeParams{
			MessageID:        newMessageID(),
			Action:           receiveURI,
			ResourceURI:      shellURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: formatTimeout(operationTimeout),
			MaxEnvelopeSize:  maxEnvelopeSize,
			ShellID:          escapeXML(shellID),
			CommandID:        escapeXML(commandID),
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := receiveOutputTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build receive output envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// buildSignalEnvelope builds the SOAP envelope for sending a signal.
func buildSignalEnvelope(endpoint, shellID, commandID, signal string, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	data := templateData{
		envelopeParams: envelopeParams{
			MessageID:        newMessageID(),
			Action:           signalURI,
			ResourceURI:      shellURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: formatTimeout(operationTimeout),
			MaxEnvelopeSize:  maxEnvelopeSize,
			ShellID:          escapeXML(shellID),
			CommandID:        escapeXML(commandID),
			Signal:           signal,
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := signalTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build signal envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// buildDeleteShellEnvelope builds the SOAP envelope for deleting a shell.
func buildDeleteShellEnvelope(endpoint, shellID string, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	data := templateData{
		envelopeParams: envelopeParams{
			MessageID:        newMessageID(),
			Action:           deleteURI,
			ResourceURI:      shellURI,
			Endpoint:         escapeXML(endpoint),
			OperationTimeout: formatTimeout(operationTimeout),
			MaxEnvelopeSize:  maxEnvelopeSize,
			ShellID:          escapeXML(shellID),
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := deleteShellTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to build delete shell envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// sendInputTemplate creates a SOAP envelope for sending input to a command.
var sendInputTemplate = template.Must(template.New("sendInput").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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
    <w:SelectorSet>
      <w:Selector Name="ShellId">{{.ShellID}}</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin" CommandId="{{.CommandID}}"{{if .EOF}} End="true"{{end}}>{{.InputData}}</rsp:Stream>
    </rsp:Send>
  </s:Body>
</s:Envelope>`))

// sendInputParams extends envelopeParams with input-specific fields.
type sendInputParams struct {
	envelopeParams
	InputData string
	EOF       bool
}

// sendInputTemplateData wraps sendInputParams with namespaces.
type sendInputTemplateData struct {
	sendInputParams
	Namespaces string
}

// buildSendInputEnvelope builds the SOAP envelope for sending input to stdin.
func buildSendInputEnvelope(endpoint, shellID, commandID string, data []byte, eof bool, maxEnvelopeSize int, operationTimeout time.Duration) ([]byte, error) {
	// Base64 encode the input data
	inputData := ""
	if len(data) > 0 {
		inputData = base64.StdEncoding.EncodeToString(data)
	}

	templateData := sendInputTemplateData{
		sendInputParams: sendInputParams{
			envelopeParams: envelopeParams{
				MessageID:        newMessageID(),
				Action:           sendURI,
				ResourceURI:      shellURI,
				Endpoint:         escapeXML(endpoint),
				OperationTimeout: formatTimeout(operationTimeout),
				MaxEnvelopeSize:  maxEnvelopeSize,
				ShellID:          escapeXML(shellID),
				CommandID:        escapeXML(commandID),
			},
			InputData: inputData,
			EOF:       eof,
		},
		Namespaces: xmlNamespaces,
	}

	var buf bytes.Buffer
	if err := sendInputTemplate.Execute(&buf, templateData); err != nil {
		return nil, fmt.Errorf("failed to build send input envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// escapeXML escapes XML special characters.
func escapeXML(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// Response parsing structures

// Envelope represents a SOAP envelope response.
type soapEnvelope struct {
	XMLName xml.Name   `xml:"Envelope"`
	Header  soapHeader `xml:"Header"`
	Body    soapBody   `xml:"Body"`
}

type soapHeader struct {
	Action string `xml:"Action"`
}

type soapBody struct {
	Shell           *shellResponse     `xml:"Shell"`
	CommandResponse *commandResponse   `xml:"CommandResponse"`
	ReceiveResponse *receiveResponse   `xml:"ReceiveResponse"`
	Fault           *soapFaultResponse `xml:"Fault"`
}

type shellResponse struct {
	ShellId string `xml:"ShellId"`
}

type commandResponse struct {
	CommandId string `xml:"CommandId"`
}

type receiveResponse struct {
	Stream       []streamElement `xml:"Stream"`
	CommandState *commandState   `xml:"CommandState"`
}

type streamElement struct {
	Name      string `xml:"Name,attr"`
	CommandId string `xml:"CommandId,attr"`
	End       bool   `xml:"End,attr"`
	Content   string `xml:",chardata"`
}

type commandState struct {
	CommandId string `xml:"CommandId,attr"`
	State     string `xml:"State,attr"`
	ExitCode  int    `xml:"ExitCode"`
}

type soapFaultResponse struct {
	Code   faultCode   `xml:"Code"`
	Reason faultReason `xml:"Reason"`
	Detail string      `xml:"Detail"`
}

type faultCode struct {
	Value   string     `xml:"Value"`
	Subcode *faultCode `xml:"Subcode"`
}

type faultReason struct {
	Text string `xml:"Text"`
}

// parseCreateShellResponse parses the response from creating a shell.
func parseCreateShellResponse(data []byte) (string, error) {
	var envelope soapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse create shell response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return "", parseFault(envelope.Body.Fault)
	}

	if envelope.Body.Shell == nil || envelope.Body.Shell.ShellId == "" {
		return "", ErrShellNotCreated
	}

	return envelope.Body.Shell.ShellId, nil
}

// parseExecuteCommandResponse parses the response from executing a command.
func parseExecuteCommandResponse(data []byte) (string, error) {
	var envelope soapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse execute command response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return "", parseFault(envelope.Body.Fault)
	}

	if envelope.Body.CommandResponse == nil || envelope.Body.CommandResponse.CommandId == "" {
		return "", ErrCommandNotStarted
	}

	return envelope.Body.CommandResponse.CommandId, nil
}

// ReceiveResult holds the result of a receive operation.
type ReceiveResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Done     bool
}

// parseReceiveResponse parses the response from receiving output.
func parseReceiveResponse(data []byte) (*ReceiveResult, error) {
	var envelope soapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse receive response: %w", err)
	}

	if envelope.Body.Fault != nil {
		return nil, parseFault(envelope.Body.Fault)
	}

	result := &ReceiveResult{}

	if envelope.Body.ReceiveResponse != nil {
		for _, stream := range envelope.Body.ReceiveResponse.Stream {
			decoded, err := decodeBase64(stream.Content)
			if err != nil {
				continue
			}
			switch stream.Name {
			case "stdout":
				result.Stdout = append(result.Stdout, decoded...)
			case "stderr":
				result.Stderr = append(result.Stderr, decoded...)
			}
		}

		if envelope.Body.ReceiveResponse.CommandState != nil {
			result.ExitCode = envelope.Body.ReceiveResponse.CommandState.ExitCode
			result.Done = envelope.Body.ReceiveResponse.CommandState.State == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
		}
	}

	return result, nil
}

// parseFault converts a SOAP fault response to an error.
func parseFault(fault *soapFaultResponse) error {
	code := fault.Code.Value
	if fault.Code.Subcode != nil {
		code = fault.Code.Subcode.Value
	}
	return &SOAPFault{
		Code:   code,
		Reason: fault.Reason.Text,
		Detail: fault.Detail,
	}
}

// parseSOAPFaultFromResponse attempts to extract a SOAP fault from any response body.
// Returns nil if no fault is found.
func parseSOAPFaultFromResponse(data []byte) error {
	var envelope soapEnvelope
	if err := xml.Unmarshal(data, &envelope); err != nil {
		return nil
	}
	if envelope.Body.Fault != nil {
		return parseFault(envelope.Body.Fault)
	}
	return nil
}

// decodeBase64 decodes a base64 string, handling empty strings and whitespace.
func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}
