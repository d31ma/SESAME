package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const maxInitializationEnvironmentBytes = 64 << 10

// loadInitializationEnvironment reads an explicitly selected dotenv file.
// It returns values to the caller instead of mutating the process environment,
// which keeps unrelated variables and secrets out of SESAME and its children.
func loadInitializationEnvironment(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = file.Close() }()

	values, err := parseInitializationEnvironment(file)
	if err != nil {
		return nil, err
	}
	return values, nil
}

// parseInitializationEnvironment implements the deliberately small dotenv
// grammar accepted by sesame init: comments, optional export prefixes, and
// unquoted, single-quoted, or double-quoted assignments. Expansion and command
// substitution are never performed.
func parseInitializationEnvironment(reader io.Reader) (map[string]string, error) {
	encoded, err := io.ReadAll(io.LimitReader(reader, maxInitializationEnvironmentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(encoded) > maxInitializationEnvironmentBytes {
		return nil, fmt.Errorf("exceeds the %d-byte limit", maxInitializationEnvironmentBytes)
	}
	if !utf8.Valid(encoded) {
		return nil, fmt.Errorf("is not valid UTF-8")
	}
	if bytes.IndexByte(encoded, 0) >= 0 {
		return nil, fmt.Errorf("contains a NUL byte")
	}

	values := make(map[string]string)
	for index, line := range strings.Split(string(encoded), "\n") {
		lineNumber := index + 1
		line = strings.TrimSuffix(line, "\r")
		if index == 0 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = trimExportPrefix(line)

		name, encodedValue, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found {
			return nil, fmt.Errorf("line %d has no assignment", lineNumber)
		}
		if !validEnvironmentName(name) {
			return nil, fmt.Errorf("line %d has an invalid variable name", lineNumber)
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("line %d repeats variable %s", lineNumber, name)
		}

		value, err := parseEnvironmentValue(encodedValue)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		values[name] = value
	}
	return values, nil
}

func trimExportPrefix(line string) string {
	if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
		return strings.TrimSpace(line[len("export"):])
	}
	return line
}

func validEnvironmentName(name string) bool {
	if name == "" || !environmentNameStart(name[0]) {
		return false
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if !environmentNameStart(character) && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func environmentNameStart(character byte) bool {
	return character == '_' || character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z'
}

func parseEnvironmentValue(encoded string) (string, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return "", nil
	}

	switch encoded[0] {
	case '\'':
		return parseSingleQuotedValue(encoded)
	case '"':
		return parseDoubleQuotedValue(encoded)
	default:
		return trimInlineComment(encoded), nil
	}
}

func parseSingleQuotedValue(encoded string) (string, error) {
	end := strings.IndexByte(encoded[1:], '\'')
	if end < 0 {
		return "", fmt.Errorf("unterminated single-quoted value")
	}
	end++
	if err := validateQuotedSuffix(encoded[end+1:]); err != nil {
		return "", err
	}
	return encoded[1:end], nil
}

func parseDoubleQuotedValue(encoded string) (string, error) {
	var value strings.Builder
	for index := 1; index < len(encoded); index++ {
		character := encoded[index]
		if character == '"' {
			if err := validateQuotedSuffix(encoded[index+1:]); err != nil {
				return "", err
			}
			return value.String(), nil
		}
		if character != '\\' {
			value.WriteByte(character)
			continue
		}
		if index+1 == len(encoded) {
			return "", fmt.Errorf("unterminated double-quoted escape")
		}
		index++
		escaped := encoded[index]
		switch escaped {
		case 'n':
			value.WriteByte('\n')
		case 'r':
			value.WriteByte('\r')
		case 't':
			value.WriteByte('\t')
		case '"', '\\':
			value.WriteByte(escaped)
		default:
			// Preserve unknown escapes. This keeps Windows paths intact and
			// avoids inventing shell semantics.
			value.WriteByte('\\')
			value.WriteByte(escaped)
		}
	}
	return "", fmt.Errorf("unterminated double-quoted value")
}

func validateQuotedSuffix(suffix string) error {
	suffix = strings.TrimSpace(suffix)
	if suffix == "" || strings.HasPrefix(suffix, "#") {
		return nil
	}
	return fmt.Errorf("unexpected content after quoted value")
}

func trimInlineComment(value string) string {
	for index := 1; index < len(value); index++ {
		if value[index] == '#' && (value[index-1] == ' ' || value[index-1] == '\t') {
			return strings.TrimSpace(value[:index])
		}
	}
	return strings.TrimSpace(value)
}
