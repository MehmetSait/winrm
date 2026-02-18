package winrm

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"unicode/utf16"
)

// Shell represents a persistent WinRM shell session.
// A shell maintains a remote PowerShell/cmd process that can execute
// multiple commands without the overhead of creating new processes.
// It is safe for concurrent use from multiple goroutines.
type Shell struct {
	client  *Client
	shellID string
	closed  bool
	mu      sync.Mutex
}

// ID returns the shell ID.
func (s *Shell) ID() string {
	return s.shellID
}

// IsClosed returns true if the shell is closed.
func (s *Shell) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close closes the shell and releases server resources.
// It's safe to call Close multiple times.
func (s *Shell) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	envelope, err := buildDeleteShellEnvelope(
		s.client.endpoint,
		s.shellID,
		s.client.config.MaxEnvelopeSize,
		s.client.config.OperationTimeout,
	)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.client.config.SendTimeout)
	defer cancel()

	_, _ = s.client.send(ctx, envelope)
	return nil
}

// Execute executes a command in the shell and waits for completion.
func (s *Shell) Execute(command string) (*CommandResult, error) {
	return s.ExecuteContext(context.Background(), command)
}

// ExecuteContext executes a command with context support.
func (s *Shell) ExecuteContext(ctx context.Context, command string) (*CommandResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrShellClosed
	}
	s.mu.Unlock()

	cmd := s.NewCommand(command)
	return cmd.RunContext(ctx)
}

// ExecutePowerShell executes a PowerShell script in the shell.
// The script is automatically encoded as UTF-16LE Base64.
func (s *Shell) ExecutePowerShell(script string) (*CommandResult, error) {
	return s.ExecutePowerShellContext(context.Background(), script)
}

// ExecutePowerShellContext executes a PowerShell script with context support.
func (s *Shell) ExecutePowerShellContext(ctx context.Context, script string) (*CommandResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrShellClosed
	}
	s.mu.Unlock()

	cmd := s.NewPowerShellCommand(script)
	return cmd.RunContext(ctx)
}

// NewCommand creates a new command for execution in this shell.
func (s *Shell) NewCommand(command string) *Command {
	return &Command{
		shell:   s,
		command: command,
	}
}

// NewCommandWithArgs creates a new command with separate arguments.
func (s *Shell) NewCommandWithArgs(command, arguments string) *Command {
	return &Command{
		shell:     s,
		command:   command,
		arguments: arguments,
	}
}

// NewPowerShellCommand creates a new PowerShell command.
// The script is automatically encoded as UTF-16LE Base64 to handle
// special characters and non-ASCII text (like Turkish characters).
// Progress bars are disabled to prevent stderr pollution.
func (s *Shell) NewPowerShellCommand(script string) *Command {
	// Disable progress bars which are considered as stderr
	script = "$ProgressPreference = 'SilentlyContinue';" + script
	encoded := EncodePowerShellScript(script)
	return &Command{
		shell:     s,
		command:   "powershell.exe",
		arguments: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded,
	}
}

// Command represents a command to be executed in a shell.
type Command struct {
	shell     *Shell
	command   string
	arguments string
	commandID string
	started   bool
	finished  bool
	mu        sync.Mutex
}

// Run executes the command and returns the result.
func (c *Command) Run() (*CommandResult, error) {
	return c.RunContext(context.Background())
}

// RunContext executes the command with context support.
func (c *Command) RunContext(ctx context.Context) (*CommandResult, error) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return nil, ErrCommandAlreadyStarted
	}
	c.started = true
	c.mu.Unlock()

	// Start the command
	commandID, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	c.commandID = commandID

	// Receive output
	result, err := c.receive(ctx)
	if err != nil {
		_ = c.signal(ctx, signalTerminate)
		return nil, err
	}

	// Signal completion
	_ = c.signal(ctx, signalTerminate)
	c.mu.Lock()
	c.finished = true
	c.mu.Unlock()

	return result, nil
}

// Start starts the command without waiting for completion.
// Use this with SendInput and Receive for interactive commands.
func (c *Command) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return ErrCommandAlreadyStarted
	}
	c.started = true
	c.mu.Unlock()

	commandID, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.commandID = commandID
	return nil
}

// SendInput sends input data to the command's stdin.
// Set eof to true when sending the last chunk of input.
func (c *Command) SendInput(ctx context.Context, data []byte, eof bool) error {
	c.mu.Lock()
	if !c.started || c.commandID == "" {
		c.mu.Unlock()
		return ErrCommandNotStarted
	}
	c.mu.Unlock()

	envelope, err := buildSendInputEnvelope(
		c.shell.client.endpoint,
		c.shell.shellID,
		c.commandID,
		data,
		eof,
		c.shell.client.config.MaxEnvelopeSize,
		c.shell.client.config.OperationTimeout,
	)
	if err != nil {
		return err
	}

	_, err = c.shell.client.send(ctx, envelope)
	return err
}

// Receive receives output from the command.
// Returns partial results. Call repeatedly until Done is true.
func (c *Command) Receive(ctx context.Context) (*ReceiveResult, error) {
	c.mu.Lock()
	if !c.started || c.commandID == "" {
		c.mu.Unlock()
		return nil, ErrCommandNotStarted
	}
	c.mu.Unlock()

	envelope, err := buildReceiveOutputEnvelope(
		c.shell.client.endpoint,
		c.shell.shellID,
		c.commandID,
		c.shell.client.config.MaxEnvelopeSize,
		c.shell.client.config.OperationTimeout,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.shell.client.send(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to receive output: %w", err)
	}

	return parseReceiveResponse(resp)
}

// Close terminates the command and releases resources.
func (c *Command) Close() error {
	c.mu.Lock()
	if !c.started || c.commandID == "" {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.shell.client.config.SendTimeout)
	defer cancel()

	return c.signal(ctx, signalTerminate)
}

const signalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"

// RunAndUnmarshal executes the command and unmarshals JSON output into v.
func (c *Command) RunAndUnmarshal(v interface{}) error {
	return c.RunAndUnmarshalContext(context.Background(), v)
}

// RunAndUnmarshalContext executes the command and unmarshals JSON output with context.
func (c *Command) RunAndUnmarshalContext(ctx context.Context, v interface{}) error {
	result, err := c.RunContext(ctx)
	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		return &PowerShellError{
			Message:  "command failed",
			ExitCode: result.ExitCode,
			Stderr:   result.Stderr(),
		}
	}

	return UnmarshalJSON(result.Stdout(), v)
}

// RunAndUnmarshalCSV executes the command and unmarshals CSV output.
func (c *Command) RunAndUnmarshalCSV() ([]map[string]string, error) {
	return c.RunAndUnmarshalCSVContext(context.Background())
}

// RunAndUnmarshalCSVContext executes the command and unmarshals CSV output with context.
func (c *Command) RunAndUnmarshalCSVContext(ctx context.Context) ([]map[string]string, error) {
	result, err := c.RunContext(ctx)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		return nil, &PowerShellError{
			Message:  "command failed",
			ExitCode: result.ExitCode,
			Stderr:   result.Stderr(),
		}
	}

	return UnmarshalCSV(result.Stdout())
}

// RunAndUnmarshalCSVTo executes the command and unmarshals CSV output into typed slice.
func RunAndUnmarshalCSVTo[T any](c *Command) ([]T, error) {
	return RunAndUnmarshalCSVToContext[T](context.Background(), c)
}

// RunAndUnmarshalCSVToContext executes with context and unmarshals CSV output into typed slice.
func RunAndUnmarshalCSVToContext[T any](ctx context.Context, c *Command) ([]T, error) {
	result, err := c.RunContext(ctx)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		return nil, &PowerShellError{
			Message:  "command failed",
			ExitCode: result.ExitCode,
			Stderr:   result.Stderr(),
		}
	}

	return UnmarshalCSVTo[T](result.Stdout())
}

// start starts the command execution.
func (c *Command) start(ctx context.Context) (string, error) {
	envelope, err := buildExecuteCommandEnvelope(
		c.shell.client.endpoint,
		c.shell.shellID,
		c.command,
		c.arguments,
		c.shell.client.config.MaxEnvelopeSize,
		c.shell.client.config.OperationTimeout,
	)
	if err != nil {
		return "", err
	}

	resp, err := c.shell.client.sendWithRetry(ctx, envelope)
	if err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	return parseExecuteCommandResponse(resp)
}

// receive receives the command output.
func (c *Command) receive(ctx context.Context) (*CommandResult, error) {
	result := &CommandResult{
		stdout: make([]byte, 0, 4096),
		stderr: make([]byte, 0, 1024),
	}

	for {
		envelope, err := buildReceiveOutputEnvelope(
			c.shell.client.endpoint,
			c.shell.shellID,
			c.commandID,
			c.shell.client.config.MaxEnvelopeSize,
			c.shell.client.config.OperationTimeout,
		)
		if err != nil {
			return nil, err
		}

		resp, err := c.shell.client.send(ctx, envelope)
		if err != nil {
			return nil, fmt.Errorf("failed to receive output: %w", err)
		}

		recvResult, err := parseReceiveResponse(resp)
		if err != nil {
			return nil, err
		}

		result.stdout = append(result.stdout, recvResult.Stdout...)
		result.stderr = append(result.stderr, recvResult.Stderr...)

		if recvResult.Done {
			result.ExitCode = recvResult.ExitCode
			break
		}
	}

	return result, nil
}

// signal sends a signal to the command.
func (c *Command) signal(ctx context.Context, code string) error {
	envelope, err := buildSignalEnvelope(
		c.shell.client.endpoint,
		c.shell.shellID,
		c.commandID,
		code,
		c.shell.client.config.MaxEnvelopeSize,
		c.shell.client.config.OperationTimeout,
	)
	if err != nil {
		return err
	}

	_, err = c.shell.client.send(ctx, envelope)
	return err
}

// CommandResult holds the result of a command execution.
type CommandResult struct {
	stdout   []byte
	stderr   []byte
	ExitCode int
}

// Stdout returns the standard output as a string.
func (r *CommandResult) Stdout() string {
	return string(r.stdout)
}

// Stderr returns the standard error as a string.
func (r *CommandResult) Stderr() string {
	return string(r.stderr)
}

// StdoutBytes returns the standard output as bytes.
func (r *CommandResult) StdoutBytes() []byte {
	return r.stdout
}

// StderrBytes returns the standard error as bytes.
func (r *CommandResult) StderrBytes() []byte {
	return r.stderr
}

// Success returns true if the command exited with code 0.
func (r *CommandResult) Success() bool {
	return r.ExitCode == 0
}

// EncodePowerShellScript encodes a PowerShell script as UTF-16LE Base64.
// This handles special characters and non-ASCII text properly.
func EncodePowerShellScript(script string) string {
	// Convert to UTF-16LE
	utf16Codes := utf16.Encode([]rune(script))
	utf16Bytes := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		utf16Bytes[i*2] = byte(code)
		utf16Bytes[i*2+1] = byte(code >> 8)
	}

	// Encode to Base64
	return base64.StdEncoding.EncodeToString(utf16Bytes)
}

// Batch represents a batch of commands to execute sequentially.
type Batch struct {
	shell    *Shell
	commands []*Command
	results  []*CommandResult
	errors   []error
}

// NewBatch creates a new batch for executing multiple commands.
func (s *Shell) NewBatch() *Batch {
	return &Batch{
		shell:    s,
		commands: make([]*Command, 0, 10),
	}
}

// Add adds a command to the batch.
func (b *Batch) Add(command string) *Batch {
	b.commands = append(b.commands, b.shell.NewCommand(command))
	return b
}

// AddPowerShell adds a PowerShell command to the batch.
func (b *Batch) AddPowerShell(script string) *Batch {
	b.commands = append(b.commands, b.shell.NewPowerShellCommand(script))
	return b
}

// Len returns the number of commands in the batch.
func (b *Batch) Len() int {
	return len(b.commands)
}

// Run executes all commands in the batch sequentially.
func (b *Batch) Run() error {
	return b.RunContext(context.Background())
}

// RunContext executes all commands with context support.
func (b *Batch) RunContext(ctx context.Context) error {
	b.results = make([]*CommandResult, len(b.commands))
	b.errors = make([]error, len(b.commands))

	for i, cmd := range b.commands {
		select {
		case <-ctx.Done():
			for j := i; j < len(b.commands); j++ {
				b.errors[j] = ctx.Err()
			}
			return ctx.Err()
		default:
		}

		result, err := cmd.RunContext(ctx)
		b.results[i] = result
		b.errors[i] = err
	}

	return nil
}

// Results returns the results of all commands.
func (b *Batch) Results() []*CommandResult {
	return b.results
}

// Errors returns any errors that occurred.
func (b *Batch) Errors() []error {
	return b.errors
}

// HasErrors returns true if any command failed.
func (b *Batch) HasErrors() bool {
	for _, err := range b.errors {
		if err != nil {
			return true
		}
	}
	return false
}

// SuccessCount returns the number of successful commands.
func (b *Batch) SuccessCount() int {
	count := 0
	for i, result := range b.results {
		if b.errors[i] == nil && result != nil && result.Success() {
			count++
		}
	}
	return count
}
