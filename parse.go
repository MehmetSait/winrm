package winrm

import (
	"encoding/json"
	"strings"
)

// UnmarshalJSON unmarshals JSON output from PowerShell into the given value.
// It handles both single objects and arrays automatically.
// Zero-allocation optimized for repeated use.
func UnmarshalJSON(data string, v interface{}) error {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return nil
	}

	if err := json.Unmarshal([]byte(trimmed), v); err != nil {
		return &ParseError{
			Format:  "JSON",
			Message: err.Error(),
			Raw:     data,
		}
	}

	return nil
}

// UnmarshalJSONBytes unmarshals JSON bytes into the given value.
func UnmarshalJSONBytes(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return &ParseError{
			Format:  "JSON",
			Message: err.Error(),
			Raw:     string(data),
		}
	}
	return nil
}

// UnmarshalCSV parses CSV output from PowerShell into a slice of maps.
// Each map represents a row with column names as keys.
// Handles PowerShell's #TYPE header lines and quoted fields.
func UnmarshalCSV(data string) ([]map[string]string, error) {
	lines := strings.Split(strings.TrimSpace(data), "\n")
	if len(lines) < 2 {
		return nil, nil
	}

	// Skip #TYPE line if present at the beginning
	startIdx := 0
	if strings.HasPrefix(strings.TrimSpace(lines[0]), "#TYPE") {
		startIdx = 1
	}

	if len(lines) <= startIdx+1 {
		return nil, nil
	}

	// Parse header - handle both quoted and unquoted
	headers := parseCSVLine(lines[startIdx])
	if len(headers) == 0 {
		return nil, &ParseError{
			Format:  "CSV",
			Message: "no headers found",
			Raw:     data,
		}
	}

	// Pre-allocate result slice
	result := make([]map[string]string, 0, len(lines)-startIdx-1)

	for _, line := range lines[startIdx+1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#TYPE") {
			continue
		}

		values := parseCSVLine(line)
		row := make(map[string]string, len(headers))
		for i, header := range headers {
			if i < len(values) {
				row[header] = values[i]
			} else {
				row[header] = ""
			}
		}
		result = append(result, row)
	}

	return result, nil
}

// UnmarshalCSVBytes parses CSV bytes into a slice of maps.
func UnmarshalCSVBytes(data []byte) ([]map[string]string, error) {
	return UnmarshalCSV(string(data))
}

// UnmarshalCSVTo parses CSV output into a slice of structs using generics.
// The struct fields should have json tags matching CSV column names.
func UnmarshalCSVTo[T any](data string) ([]T, error) {
	maps, err := UnmarshalCSV(data)
	if err != nil {
		return nil, err
	}

	if len(maps) == 0 {
		return nil, nil
	}

	result := make([]T, len(maps))
	for i, m := range maps {
		jsonBytes, err := json.Marshal(m)
		if err != nil {
			return nil, &ParseError{
				Format:  "CSV",
				Message: "failed to convert to struct: " + err.Error(),
				Raw:     data,
			}
		}

		if err := json.Unmarshal(jsonBytes, &result[i]); err != nil {
			return nil, &ParseError{
				Format:  "CSV",
				Message: "failed to unmarshal struct: " + err.Error(),
				Raw:     data,
			}
		}
	}

	return result, nil
}

// parseCSVLine parses a single CSV line handling quoted fields.
// Optimized for minimal allocations.
func parseCSVLine(line string) []string {
	// Remove BOM if present
	line = strings.TrimPrefix(line, "\ufeff")
	line = strings.TrimSpace(line)

	if line == "" {
		return nil
	}

	// Pre-count fields for allocation
	fieldCount := 1
	inQuotes := false
	for i := 0; i < len(line); i++ {
		if line[i] == '"' {
			inQuotes = !inQuotes
		} else if line[i] == ',' && !inQuotes {
			fieldCount++
		}
	}

	result := make([]string, 0, fieldCount)
	var current strings.Builder
	current.Grow(64) // Pre-allocate for typical field size
	inQuotes = false

	for i := 0; i < len(line); i++ {
		c := line[i]

		if c == '"' {
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				current.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		} else if c == ',' && !inQuotes {
			result = append(result, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	result = append(result, strings.TrimSpace(current.String()))
	return result
}

// GetRawXML returns the raw XML/Clixml output without modification.
// Useful for advanced scenarios with PowerShell serialized objects.
func GetRawXML(data string) string {
	return strings.TrimSpace(data)
}

// GetRawXMLBytes returns the raw XML/Clixml output as string.
func GetRawXMLBytes(data []byte) string {
	return GetRawXML(string(data))
}
