package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type machineRequest struct {
	Operation  string          `json:"op"`
	RequestID  string          `json:"requestId"`
	Collection string          `json:"collection"`
	Page       *requestPage    `json:"page"`
	Data       json.RawMessage `json:"data"`
	Query      json.RawMessage `json:"query"`
}

// matchesQuery implements the subset of FYLO's query language the fake
// serves: clauses in $ops are OR'd, fields within one clause are AND'd, and
// the supported operators are $eq and numeric $gt.
func matchesQuery(data json.RawMessage, query json.RawMessage) bool {
	if len(query) == 0 {
		return true
	}
	var parsed struct {
		Ops []map[string]map[string]any `json:"$ops"`
	}
	if json.Unmarshal(query, &parsed) != nil {
		return false
	}
	if len(parsed.Ops) == 0 {
		return true
	}
	var document map[string]any
	if json.Unmarshal(data, &document) != nil {
		return false
	}
	for _, clause := range parsed.Ops {
		matched := true
		for field, operators := range clause {
			for operator, operand := range operators {
				switch operator {
				case "$eq":
					if document[field] != operand {
						matched = false
					}
				case "$gt":
					value, valueOK := document[field].(float64)
					bound, boundOK := operand.(float64)
					if !valueOK || !boundOK || value <= bound {
						matched = false
					}
				default:
					matched = false
				}
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// storedDocuments holds putData documents per collection in insertion order,
// mimicking FYLO's TTID-ascending identifiers. It is persisted to the fake
// root so restarted processes replay the same documents.
var storedDocuments = map[string][]storedDocument{}

var storePath string

type storedDocument struct {
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

func loadStore(root string) {
	if root == "" {
		return
	}
	storePath = filepath.Join(root, "fake-store.json")
	encoded, err := os.ReadFile(storePath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(encoded, &storedDocuments)
}

func saveStore() {
	if storePath == "" {
		return
	}
	encoded, err := json.Marshal(storedDocuments)
	if err != nil {
		return
	}
	_ = os.WriteFile(storePath, encoded, 0o600)
}

type requestPage struct {
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`
}

func main() {
	root := rootArgument(os.Args[1:])
	mode := filepath.Base(root)
	loadStore(root)
	maxRequestBytes := integerArgument(os.Args[1:], "--max-request-bytes", 1024)
	maxResponseBytes := integerArgument(os.Args[1:], "--max-response-bytes", 4096)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var request machineRequest
		_ = json.Unmarshal(scanner.Bytes(), &request)

		switch mode {
		case "root-locked":
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"protocolVersion": 1,
				"ok":              false,
				"op":              nil,
				"requestId":       nil,
				"durationMs":      0,
				"error": map[string]any{
					"name":    "RootLeaseError",
					"message": "synthetic competing owner",
					"code":    "EROOTLOCKED",
				},
			})
			return
		case "protocol-mismatch":
			writeResponse(2, request, true, map[string]any{"exists": false}, nil)
		case "duplicate":
			fmt.Fprintf(
				os.Stdout,
				"{\"protocolVersion\":1,\"ok\":true,\"ok\":false,\"op\":%q,\"requestId\":%q,\"durationMs\":0,\"result\":{}}\n",
				request.Operation,
				request.RequestID,
			)
		case "oversized":
			writeResponse(1, request, true, strings.Repeat("x", 2048), nil)
		case "malformed":
			_, _ = fmt.Fprintln(os.Stdout, "{not-json")
		case "unknown":
			writeCustom(request, map[string]any{"unexpected": true})
		case "missing-duration":
			response := normalResponse(request)
			delete(response, "durationMs")
			_ = json.NewEncoder(os.Stdout).Encode(response)
		case "null-duration":
			response := normalResponse(request)
			response["durationMs"] = nil
			_ = json.NewEncoder(os.Stdout).Encode(response)
		case "operation-mismatch":
			response := normalResponse(request)
			response["op"] = "getLatest"
			_ = json.NewEncoder(os.Stdout).Encode(response)
		case "request-mismatch":
			response := normalResponse(request)
			response["requestId"] = "different-request"
			_ = json.NewEncoder(os.Stdout).Encode(response)
		case "runtime-mismatch":
			writeIdentity(request, mode, maxRequestBytes, maxResponseBytes)
		case "frame-mismatch":
			writeIdentity(request, mode, maxRequestBytes+1, maxResponseBytes)
		case "target-mismatch",
			"missing-handshake",
			"missing-exclusive-root",
			"missing-vendor",
			"identity-missing-field",
			"development":
			writeIdentity(request, mode, maxRequestBytes, maxResponseBytes)
		case "stderr":
			_, _ = fmt.Fprintln(os.Stderr, strings.Repeat("x", 4096)+"diagnostic-tail")
			writeIdentityOrNormal(request, mode, maxRequestBytes, maxResponseBytes)
		case "block":
			if request.Operation == "handshake" {
				writeIdentity(request, mode, maxRequestBytes, maxResponseBytes)
				continue
			}
			_, _ = fmt.Fprintln(os.Stderr, "block-started")
			time.Sleep(time.Hour)
		default:
			if request.Operation == "fail" {
				writeResponse(1, request, false, nil, map[string]any{
					"name":    "Error",
					"message": "synthetic failure",
					"code":    "EFAIL",
				})
				continue
			}
			if request.Operation == "putData" {
				// Mirror FYLO's intended document model: embedded arrays of
				// objects are rejected at any depth (they belong in their own
				// collection), so SESAME schemas that would break on the real
				// runtime break here too.
				if containsObjectArray(request.Data) {
					writeResponse(1, request, false, nil, map[string]any{
						"name":    "AggregateError",
						"message": "Document put failed and rollback was incomplete",
						"code":    "EUNKNOWN",
					})
					continue
				}
				documents := storedDocuments[request.Collection]
				id := fmt.Sprintf("FAKE-%06d", len(documents)+1)
				storedDocuments[request.Collection] = append(documents, storedDocument{
					ID:   id,
					Data: request.Data,
				})
				saveStore()
				writeResponse(1, request, true, id, nil)
				continue
			}
			if request.Operation == "findDocs" && request.Page != nil {
				writeDocumentPage(request, mode)
				continue
			}
			writeIdentityOrNormal(request, mode, maxRequestBytes, maxResponseBytes)
		}
	}
	if mode == "stubborn" {
		time.Sleep(time.Hour)
	}
}

func writeIdentityOrNormal(
	request machineRequest,
	mode string,
	maxRequestBytes int,
	maxResponseBytes int,
) {
	if request.Operation == "handshake" {
		writeIdentity(request, mode, maxRequestBytes, maxResponseBytes)
		return
	}
	writeNormal(request)
}

func writeIdentity(
	request machineRequest,
	mode string,
	maxRequestBytes int,
	maxResponseBytes int,
) {
	runtimeVersion := "26.30.06"
	if mode == "runtime-mismatch" {
		runtimeVersion = "99.0.0"
	}
	buildKind := "release"
	commit := "0123456789abcdef0123456789abcdef01234567"
	if mode == "development" {
		buildKind = "development-compiled"
		commit = "unknown"
	}
	exclusiveRoot := mode != "missing-exclusive-root"
	handshake := mode != "missing-handshake"
	vendorAvailable := mode != "missing-vendor"
	buildTarget := runtimeTarget()
	if mode == "target-mismatch" {
		buildTarget = "unsupported-target"
	}
	machine := map[string]any{
		"framing":                    "ndjson",
		"encoding":                   "utf-8",
		"delimiter":                  "LF",
		"delimiterCountsTowardLimit": false,
		"maxRequestBytes":            maxRequestBytes,
		"maxResponseBytes":           maxResponseBytes,
		"duplicateKeys":              "rejected",
		"truncatedFrame":             "error-and-terminate",
		"malformedFrame":             "error-and-resume-at-next-LF",
	}
	if mode == "identity-missing-field" {
		delete(machine, "delimiterCountsTowardLimit")
	}
	writeResponse(1, request, true, map[string]any{
		"runtimeVersion":  runtimeVersion,
		"protocolVersion": 1,
		"commit":          commit,
		"buildTarget":     buildTarget,
		"buildKind":       buildKind,
		"dependencies": map[string]any{
			"chex": map[string]any{
				"requiredVersion": "26.28.02",
				"available":       vendorAvailable,
			},
			"ttid": map[string]any{
				"requiredVersion": "26.28.02",
				"available":       vendorAvailable,
			},
		},
		"machine": machine,
		"capabilities": map[string]any{
			"handshake":       handshake,
			"exclusiveRoot":   exclusiveRoot,
			"queryPagination": paginationCapability(mode),
		},
	}, nil)
}

func paginationCapability(mode string) any {
	if mode == "missing-pagination" {
		return nil
	}
	return map[string]any{
		"version":          1,
		"operations":       []string{"findDocs", "findDeletedDocs"},
		"defaultItems":     256,
		"maxItems":         4096,
		"maxSnapshotBytes": 1073741824,
		"cursorTtlMs":      900000,
		"ordering":         "ttid-binary-ascending",
		"scope":            "persistent-process",
		"restartPolicy":    "restart-from-first-page",
		"mutationPolicy":   "snapshot-at-first-page",
	}
}

func containsObjectArray(data json.RawMessage) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	return valueContainsObjectArray(value)
}

func valueContainsObjectArray(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if _, isObject := item.(map[string]any); isObject {
				return true
			}
			if valueContainsObjectArray(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if valueContainsObjectArray(item) {
				return true
			}
		}
	}
	return false
}

const pagedDocumentTotal = 13

// pagedDataset returns the ordered documents served for a collection: stored
// putData documents, or a synthetic 13-item dataset for the fixed collection
// name used by the adapter's pagination tests.
func pagedDataset(collection string) []storedDocument {
	if collection != "security-events" {
		return storedDocuments[collection]
	}
	documents := make([]storedDocument, 0, pagedDocumentTotal)
	for index := range pagedDocumentTotal {
		data, _ := json.Marshal(map[string]any{
			"kind": "security-event",
			"n":    index + 1,
		})
		documents = append(documents, storedDocument{
			ID:   fmt.Sprintf("DOC-%02d", index+1),
			Data: data,
		})
	}
	return documents
}

func writeDocumentPage(request machineRequest, mode string) {
	dataset := make([]storedDocument, 0)
	for _, document := range pagedDataset(request.Collection) {
		if matchesQuery(document.Data, request.Query) {
			dataset = append(dataset, document)
		}
	}
	total := len(dataset)
	offset := 0
	if request.Page.Cursor != "" {
		parsed, err := fmt.Sscanf(request.Page.Cursor, "fake-cursor-%d", &offset)
		if parsed != 1 || err != nil || offset < 1 || offset >= total {
			writeResponse(1, request, false, nil, map[string]any{
				"name":    "MachineCursorError",
				"message": "Machine query cursor is invalid, expired, or belongs to another process",
				"code":    "EINVALIDCURSOR",
			})
			return
		}
	}

	count := min(request.Page.Limit, total-offset)
	if mode == "page-overflow" {
		count = min(request.Page.Limit+1, total-offset)
	}
	items := make(map[string]any, count)
	for _, document := range dataset[offset : offset+count] {
		items[document.ID] = json.RawMessage(document.Data)
	}
	reportedCount := len(items)
	if mode == "page-miscount" {
		reportedCount++
	}
	var nextCursor any
	if offset+count < total {
		nextCursor = fmt.Sprintf("fake-cursor-%d", offset+count)
	}
	writeResponse(1, request, true, map[string]any{
		"items":      items,
		"nextCursor": nextCursor,
		"page":       map[string]any{"count": reportedCount, "limit": request.Page.Limit},
	}, nil)
}

func writeNormal(request machineRequest) {
	_ = json.NewEncoder(os.Stdout).Encode(normalResponse(request))
}

func writeCustom(request machineRequest, fields map[string]any) {
	response := normalResponse(request)
	for field, value := range fields {
		response[field] = value
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func normalResponse(request machineRequest) map[string]any {
	return map[string]any{
		"protocolVersion": 1,
		"ok":              true,
		"op":              request.Operation,
		"requestId":       request.RequestID,
		"durationMs":      0,
		"result": map[string]any{
			"collection": request.Collection,
			"exists":     true,
		},
	}
}

func writeResponse(
	protocolVersion int,
	request machineRequest,
	ok bool,
	result any,
	failure map[string]any,
) {
	response := map[string]any{
		"protocolVersion": protocolVersion,
		"ok":              ok,
		"op":              request.Operation,
		"requestId":       request.RequestID,
		"durationMs":      0,
	}
	if ok {
		response["result"] = result
	} else {
		response["error"] = failure
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func rootArgument(arguments []string) string {
	for index := range arguments {
		if arguments[index] == "--root" && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func integerArgument(arguments []string, name string, fallback int) int {
	for index := range arguments {
		if arguments[index] == name && index+1 < len(arguments) {
			var value int
			if _, err := fmt.Sscanf(arguments[index+1], "%d", &value); err == nil {
				return value
			}
		}
	}
	return fallback
}

func runtimeTarget() string {
	operatingSystem := runtime.GOOS
	if operatingSystem == "darwin" {
		operatingSystem = "macos"
	}
	return operatingSystem + "-" + runtime.GOARCH
}
