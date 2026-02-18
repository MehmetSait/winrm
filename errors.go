package winrm

import (
	"errors"
	"fmt"
)

// Sentinel errors for the WinRM library.
var (
	// ErrShellClosed is returned when trying to use a closed shell.
	ErrShellClosed = errors.New("winrm: shell is closed")

	// ErrShellNotCreated is returned when shell creation failed.
	ErrShellNotCreated = errors.New("winrm: shell not created")

	// ErrCommandNotStarted is returned when trying to receive from an unstarted command.
	ErrCommandNotStarted = errors.New("winrm: command not started")

	// ErrCommandAlreadyStarted is returned when trying to start an already started command.
	ErrCommandAlreadyStarted = errors.New("winrm: command already started")

	// ErrConnectionFailed is returned when the connection to the WinRM server fails.
	ErrConnectionFailed = errors.New("winrm: connection failed")

	// ErrAuthenticationFailed is returned when authentication fails.
	ErrAuthenticationFailed = errors.New("winrm: authentication failed")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("winrm: operation timed out")

	// ErrMaxRetriesExceeded is returned when maximum retry attempts are exceeded.
	ErrMaxRetriesExceeded = errors.New("winrm: maximum retries exceeded")
)

// WinRMError represents a WinRM protocol error.
type WinRMError struct {
	Code    string
	Message string
	Reason  string
}

func (e *WinRMError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("winrm error [%s]: %s (%s)", e.Code, e.Message, e.Reason)
	}
	return fmt.Sprintf("winrm error [%s]: %s", e.Code, e.Message)
}

// SOAPFault represents a SOAP fault returned by the WinRM server.
type SOAPFault struct {
	Code   string
	Reason string
	Detail string
}

func (e *SOAPFault) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("soap fault [%s]: %s - %s", e.Code, e.Reason, e.Detail)
	}
	return fmt.Sprintf("soap fault [%s]: %s", e.Code, e.Reason)
}

// PowerShellError represents a PowerShell runtime error.
type PowerShellError struct {
	Message    string
	Category   string
	TargetName string
	ExitCode   int
	Stderr     string
}

func (e *PowerShellError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("powershell error (exit %d): %s\nstderr: %s", e.ExitCode, e.Message, e.Stderr)
	}
	return fmt.Sprintf("powershell error (exit %d): %s", e.ExitCode, e.Message)
}

// ErrInvalidConfig represents a configuration error.
type ErrInvalidConfig string

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("winrm: invalid config: %s", string(e))
}

// ParseError represents a parsing error for JSON/CSV/XML.
type ParseError struct {
	Format  string
	Message string
	Raw     string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("winrm: %s parse error: %s", e.Format, e.Message)
}

// IsTemporary returns true if the error is temporary and can be retried.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}

	// Check for timeout
	if errors.Is(err, ErrTimeout) {
		return true
	}

	// Check for connection errors (usually temporary)
	if errors.Is(err, ErrConnectionFailed) {
		return true
	}

	// Check for SOAP faults that are temporary
	var soapFault *SOAPFault
	if errors.As(err, &soapFault) {
		// These fault codes are typically temporary
		temporaryCodes := []string{
			"w:TimedOut",
			"w:InternalError",
			"w:ConcurrencyViolation",
		}
		for _, code := range temporaryCodes {
			if soapFault.Code == code {
				return true
			}
		}
	}

	return false
}

// IsAuthError returns true if the error is an authentication error.
func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthenticationFailed)
}

// IsPowerShellError returns true if the error is a PowerShell runtime error.
func IsPowerShellError(err error) bool {
	var psErr *PowerShellError
	return errors.As(err, &psErr)
}

// IsSOAPFault returns true if the error is a SOAP fault.
func IsSOAPFault(err error) bool {
	var soapFault *SOAPFault
	return errors.As(err, &soapFault)
}
