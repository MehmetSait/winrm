// Example: Basic WinRM connection and command execution
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/MehmetSait/winrm"
)

func main() {
	// Get connection details from environment
	host := os.Getenv("WINRM_HOST")
	username := os.Getenv("WINRM_USERNAME")
	password := os.Getenv("WINRM_PASSWORD")

	if host == "" || username == "" || password == "" {
		log.Fatal("Set WINRM_HOST, WINRM_USERNAME, WINRM_PASSWORD environment variables")
	}

	// Create client with NTLM authentication
	client, err := winrm.NewClient(&winrm.Config{
		Host:               host,
		UseHTTPS:           true,
		InsecureSkipVerify: true,
		Auth:               winrm.AuthNTLM(username, password),
		ConnectTimeout:     30 * time.Second,
		OperationTimeout:   60 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Create a persistent shell
	fmt.Println("Creating shell...")
	shell, err := client.CreateShell()
	if err != nil {
		log.Fatalf("Failed to create shell: %v", err)
	}
	defer shell.Close()
	fmt.Printf("Shell created: %s\n", shell.ID())

	// Example 1: Simple command
	fmt.Println("\n--- Example 1: Get current date ---")
	result, err := shell.ExecutePowerShell("Get-Date")
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	fmt.Printf("Output: %s", result.Stdout())

	// Example 2: JSON output with struct parsing
	fmt.Println("\n--- Example 2: Parse JSON into struct ---")
	type DateInfo struct {
		Year   int `json:"Year"`
		Month  int `json:"Month"`
		Day    int `json:"Day"`
		Hour   int `json:"Hour"`
		Minute int `json:"Minute"`
	}

	cmd := shell.NewPowerShellCommand("Get-Date | Select-Object Year, Month, Day, Hour, Minute | ConvertTo-Json")
	var dateInfo DateInfo
	if err := cmd.RunAndUnmarshal(&dateInfo); err != nil {
		log.Fatalf("Failed: %v", err)
	}
	fmt.Printf("Date: %04d-%02d-%02d %02d:%02d\n", dateInfo.Year, dateInfo.Month, dateInfo.Day, dateInfo.Hour, dateInfo.Minute)

	// Example 3: CSV parsing with generics
	fmt.Println("\n--- Example 3: CSV parsing with generics ---")
	type ServiceInfo struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      string `json:"Status"`
	}

	cmd = shell.NewPowerShellCommand(`
		Get-Service | Select-Object -First 5 Name, DisplayName, Status | ConvertTo-Csv -NoTypeInformation
	`)
	services, err := winrm.RunAndUnmarshalCSVTo[ServiceInfo](cmd)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	for _, svc := range services {
		fmt.Printf("  %s (%s) - %s\n", svc.Name, svc.DisplayName, svc.Status)
	}

	// Example 4: CSV to map (dynamic)
	fmt.Println("\n--- Example 4: CSV to map ---")
	cmd = shell.NewPowerShellCommand(`Get-Process | Select-Object -First 3 Name, Id, CPU | ConvertTo-Csv -NoTypeInformation`)
	rows, err := cmd.RunAndUnmarshalCSV()
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	for _, row := range rows {
		fmt.Printf("  Process: %s (PID: %s)\n", row["Name"], row["Id"])
	}

	// Example 5: Batch commands
	fmt.Println("\n--- Example 5: Batch Commands ---")
	batch := shell.NewBatch()
	batch.AddPowerShell("Get-Service | Measure-Object | Select-Object -ExpandProperty Count")
	batch.AddPowerShell("Get-Process | Measure-Object | Select-Object -ExpandProperty Count")
	batch.AddPowerShell("Get-Date -Format 'yyyy-MM-dd HH:mm:ss'")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := batch.RunContext(ctx); err != nil {
		log.Fatalf("Batch failed: %v", err)
	}

	fmt.Printf("Successful: %d/%d\n", batch.SuccessCount(), batch.Len())
	results := batch.Results()
	fmt.Printf("  Services: %s", results[0].Stdout())
	fmt.Printf("  Processes: %s", results[1].Stdout())
	fmt.Printf("  DateTime: %s", results[2].Stdout())

	fmt.Println("\n--- Done ---")
}
