package contract_test

import (
	"os"
	"path"
	"path/filepath"
	"testing"
)

const goSDKName = "go"

const goSDKDirectory = "server/packages"

func sdkRelativeDirectory(sdk string) string {
	if sdk == goSDKName {
		return goSDKDirectory
	}
	return path.Join("clients", sdk)
}

func sdkDirectory(root string, sdk string) string {
	return filepath.Join(root, filepath.FromSlash(sdkRelativeDirectory(sdk)))
}

func goSDKClientFile(root string) string {
	return filepath.Join(sdkDirectory(root, goSDKName), "sesame", "client.go")
}

func shippedSDKs(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}
	names := []string{goSDKName}
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names
}
