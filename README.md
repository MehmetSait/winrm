# WinRM - Modern Go WinRM Client Library

A high-performance, zero-dependency (except for NTLM) WinRM client library for Go, designed for managing Windows servers via PowerShell remoting.

## Features

- **Persistent Shell Sessions**: Keep a single PowerShell process open for multiple commands
- **Multiple Authentication Methods**: Basic, NTLM (NTLMv2), Kerberos*, CredSSP* (*planned)
- **Automatic PowerShell Encoding**: UTF-16LE Base64 encoding for proper handling of special characters
- **Generic JSON/CSV Parsing**: Parse output directly into Go structs using generics
- **Connection Pooling**: HTTP Keep-Alive with configurable pool sizes
- **Retry Mechanism**: Exponential backoff for transient errors
- **Context Support**: Full context.Context support for timeouts and cancellation
- **Batch Processing**: Execute thousands of commands efficiently
- **Shell Pool**: Pre-created shell pool for high-throughput scenarios

## Installation

```bash
go get github.com/MehmetSait/winrm
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/MehmetSait/winrm"
)

func main() {
    // Create client with NTLM authentication
    client, err := winrm.NewClient(&winrm.Config{
        Host:               "192.168.1.10",
        UseHTTPS:           true,
        InsecureSkipVerify: true, // For self-signed certs
        Auth:               winrm.AuthNTLM("username", "password"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create a persistent shell
    shell, err := client.CreateShell()
    if err != nil {
        log.Fatal(err)
    }
    defer shell.Close()

    // Execute PowerShell command
    result, err := shell.ExecutePowerShell("Get-Date | ConvertTo-Json")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Output:", result.Stdout())
    fmt.Println("Exit Code:", result.ExitCode)
}
```

### Quick Command Execution

```go
// Single command without managing shell
ctx := context.Background()
result, err := client.RunPowerShell(ctx, "Get-Process | Measure-Object | Select-Object -ExpandProperty Count")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Process count:", result.Stdout())
```

### JSON Parsing with Generics

```go
// Define your struct
type ProcessInfo struct {
    Name string  `json:"Name"`
    Id   int     `json:"Id"`
    CPU  float64 `json:"CPU"`
}

// Execute and unmarshal
cmd := shell.NewPowerShellCommand(`
    Get-Process | Select-Object -First 5 Name, Id, CPU | ConvertTo-Json
`)

var processes []ProcessInfo
if err := cmd.RunAndUnmarshal(&processes); err != nil {
    log.Fatal(err)
}

for _, p := range processes {
    fmt.Printf("Process: %s (PID: %d)\n", p.Name, p.Id)
}
```

### CSV Parsing with Generics

```go
// Define your struct with json tags (used for CSV mapping)
type ServiceInfo struct {
    Name        string `json:"Name"`
    DisplayName string `json:"DisplayName"`
    Status      string `json:"Status"`
}

// Execute and parse CSV into typed slice
cmd := shell.NewPowerShellCommand(`
    Get-Service | Select-Object Name, DisplayName, Status | ConvertTo-Csv -NoTypeInformation
`)

services, err := winrm.RunAndUnmarshalCSVTo[ServiceInfo](cmd)
if err != nil {
    log.Fatal(err)
}

for _, svc := range services {
    fmt.Printf("Service: %s - %s\n", svc.Name, svc.Status)
}
```

### CSV to Map (Dynamic)

```go
cmd := shell.NewPowerShellCommand(`Get-Service | ConvertTo-Csv -NoTypeInformation`)
rows, err := cmd.RunAndUnmarshalCSV()
if err != nil {
    log.Fatal(err)
}

for _, row := range rows {
    fmt.Printf("Service: %s, Status: %s\n", row["Name"], row["Status"])
}
```

### Interactive Commands (Stdin Support)

```go
// Create a command that reads from stdin
cmd := shell.NewCommand("cmd.exe")

// Start without waiting for completion
ctx := context.Background()
if err := cmd.Start(ctx); err != nil {
    log.Fatal(err)
}

// Send input to stdin
cmd.SendInput(ctx, []byte("echo Hello from stdin\r\n"), false)
cmd.SendInput(ctx, []byte("exit\r\n"), true) // EOF=true for last input

// Receive output
for {
    result, err := cmd.Receive(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Print(string(result.Stdout))
    if result.Done {
        break
    }
}
cmd.Close()
```

### Batch Processing

```go
// Execute multiple commands efficiently
batch := shell.NewBatch()
batch.AddPowerShell("Get-Service | Measure-Object | Select-Object -ExpandProperty Count")
batch.AddPowerShell("Get-Process | Measure-Object | Select-Object -ExpandProperty Count")
batch.AddPowerShell("Get-Date -Format 'yyyy-MM-dd HH:mm:ss'")

if err := batch.Run(); err != nil {
    log.Fatal(err)
}

fmt.Printf("Successful: %d/%d\n", batch.SuccessCount(), batch.Len())

for i, result := range batch.Results() {
    if batch.Errors()[i] != nil {
        fmt.Printf("Command %d failed: %v\n", i, batch.Errors()[i])
        continue
    }
    fmt.Printf("Command %d: %s", i, result.Stdout())
}
```

### Shell Pool for High Throughput

```go
// Create a pool of 5 pre-created shells
pool, err := client.NewPool(5)
if err != nil {
    log.Fatal(err)
}
defer pool.Close()

// Use shells from the pool
ctx := context.Background()
shell, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

result, err := shell.ExecutePowerShell("Get-Date")
if err != nil {
    log.Fatal(err)
}
fmt.Println(result.Stdout())

// Return shell to pool for reuse
pool.Put(shell)
```

## Authentication Methods

### Basic Authentication
```go
// Note: Use only with HTTPS
auth := winrm.AuthBasic("username", "password")
```

### NTLM Authentication
```go
// Simple NTLM
auth := winrm.AuthNTLM("username", "password")

// NTLM with explicit domain
auth := winrm.AuthNTLMWithDomain("DOMAIN", "username", "password")

// Or use domain\user format
auth := winrm.AuthNTLM("DOMAIN\\username", "password")
```

### Certificate Authentication
```go
config := &winrm.Config{
    Host:       "server.example.com",
    UseHTTPS:   true,
    Auth:       winrm.AuthCertificate(),
    ClientCert: pemCertBytes,
    ClientKey:  pemKeyBytes,
}
```

## Configuration Options

```go
config := &winrm.Config{
    // Connection
    Host:               "192.168.1.10",
    Port:               5986,        // 5985 for HTTP, 5986 for HTTPS
    UseHTTPS:           true,
    InsecureSkipVerify: true,        // Skip TLS verification

    // TLS (optional)
    CACert:     caCertPEM,           // Custom CA certificate
    ClientCert: clientCertPEM,       // Client certificate for mutual TLS
    ClientKey:  clientKeyPEM,        // Client private key

    // Authentication
    Auth: winrm.AuthNTLM("user", "pass"),

    // Timeouts
    ConnectTimeout:   30 * time.Second,
    SendTimeout:      60 * time.Second,
    ReceiveTimeout:   60 * time.Second,
    OperationTimeout: 60 * time.Second,

    // Protocol
    MaxEnvelopeSize: 153600,
    Locale:          "en-US",

    // Retry configuration
    RetryConfig: &winrm.RetryConfig{
        MaxRetries:   3,
        InitialDelay: 500 * time.Millisecond,
        MaxDelay:     10 * time.Second,
        Multiplier:   2.0,
    },
}
```

## Error Handling

```go
result, err := shell.ExecutePowerShell("Get-NonExistentCmdlet")
if err != nil {
    if winrm.IsAuthError(err) {
        log.Fatal("Authentication failed - check credentials")
    }
    if winrm.IsSOAPFault(err) {
        log.Fatal("WinRM protocol error:", err)
    }
    if winrm.IsTemporary(err) {
        log.Println("Temporary error, will be retried:", err)
    }
    log.Fatal(err)
}

// Check command execution result
if !result.Success() {
    fmt.Println("Command failed with exit code:", result.ExitCode)
    fmt.Println("Stderr:", result.Stderr())
}
```

## Windows Server Configuration

Enable WinRM on the Windows server:

```powershell
# Enable WinRM with HTTPS (recommended)
Enable-PSRemoting -Force
winrm quickconfig -transport:https

# Or for HTTP (testing only, not secure)
winrm quickconfig

# Configure for Basic auth (if needed)
winrm set winrm/config/service/auth '@{Basic="true"}'

# Allow unencrypted (HTTP only, not recommended)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

# Increase max envelope size for large outputs
winrm set winrm/config '@{MaxEnvelopeSizekb="500"}'
```

## Supported Windows Versions

Tested and fully supported:
- Windows Server 2012 R2 (requires WinRM 3.0+, PowerShell 4.0+)
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025
- Windows 10/11 (with WinRM enabled)

**Note**: Older versions (2008 R2, 2012) may work but are not tested. They lack native `ConvertTo-Json` support and have security limitations (TLS 1.0/1.1 only).

## Performance Tips

1. **Use Persistent Shells**: Create a shell once and reuse for multiple commands
2. **Use Shell Pool**: For concurrent operations, use `client.NewPool()`
3. **Batch Commands**: Group related commands using `shell.NewBatch()`
4. **Use CSV for Large Data**: CSV parsing is faster than JSON for large datasets
5. **Adjust Timeouts**: Set appropriate timeouts for your workload

## License

MIT License
