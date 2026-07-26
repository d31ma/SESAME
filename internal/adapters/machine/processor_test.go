package machine

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/system"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestProcessorHandlesVersionedRequestsAndContinuesAfterErrors(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		`{"protocol_version":"1","request_id":"ping-1","operation":"system.ping","parameters":{}}`,
		`{"protocol_version":"1","request_id":"version-1","operation":"system.version","parameters":{}}`,
		`{"protocol_version":"2","request_id":"bad-version","operation":"system.ping","parameters":{}}`,
		`{"protocol_version":"1","request_id":"unknown-1","operation":"identity.create","parameters":{}}`,
		`{"protocol_version":"1","request_id":"extra-1","operation":"system.ping","parameters":{},"extra":true}`,
		`{"protocol_version":"1","request_id":"duplicate-1","operation":"system.ping","operation":"system.version","parameters":{}}`,
		`not-json`,
	}, "\n") + "\n"

	var output bytes.Buffer
	processor := New(system.New(buildinfo.New("1.2.3", "abc123", "2026-07-23T00:00:00Z")), nil)
	if err := processor.Run(context.Background(), strings.NewReader(input), &output); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("response count = %d, want 7; output = %s", len(lines), output.String())
	}

	var responses []Response
	for _, line := range lines {
		var response Response
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", line, err)
		}
		responses = append(responses, response)
	}

	if !responses[0].OK || responses[0].RequestID != "ping-1" {
		t.Fatalf("ping response = %#v", responses[0])
	}
	if !responses[1].OK || responses[1].RequestID != "version-1" {
		t.Fatalf("version response = %#v", responses[1])
	}
	assertErrorCode(t, responses[2], ErrorUnsupportedProtocol)
	assertErrorCode(t, responses[3], ErrorOperationNotFound)
	assertErrorCode(t, responses[4], ErrorInvalidRequest)
	assertErrorCode(t, responses[5], ErrorInvalidRequest)
	assertErrorCode(t, responses[6], ErrorInvalidJSON)
}

func TestProcessorRejectsOversizedFrames(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(strings.Repeat("x", MaxFrameBytes+1) + "\n")
	var output bytes.Buffer

	err := New(system.New(buildinfo.New("", "", "")), nil).Run(context.Background(), input, &output)
	if err == nil {
		t.Fatal("Run() error = nil, want oversized-frame error")
	}

	var response Response
	if decodeErr := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); decodeErr != nil {
		t.Fatalf("Unmarshal() error = %v; output = %q", decodeErr, output.String())
	}
	assertErrorCode(t, response, ErrorFrameTooLarge)
}

func assertErrorCode(t *testing.T, response Response, want string) {
	t.Helper()

	if response.OK {
		t.Fatalf("response = %#v, want error %q", response, want)
	}
	if response.Error == nil || response.Error.Code != want {
		t.Fatalf("error = %#v, want code %q", response.Error, want)
	}
}

func FuzzProcessorNeverEmitsInvalidJSON(f *testing.F) {
	f.Add([]byte(`{"protocol_version":"1","request_id":"fuzz-1","operation":"system.ping","parameters":{}}`))
	f.Add([]byte(`{"protocol_version":"1","request_id":"fuzz-2","operation":"system.ping","operation":"system.version","parameters":{}}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > MaxFrameBytes+1 {
			frame = frame[:MaxFrameBytes+1]
		}

		var output bytes.Buffer
		input := append(append([]byte(nil), frame...), '\n')
		_ = New(system.New(buildinfo.New("", "", "")), nil).Run(context.Background(), bytes.NewReader(input), &output)

		for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'}) {
			if len(line) != 0 && !json.Valid(line) {
				t.Fatalf("processor emitted invalid JSON %q for input %q", line, frame)
			}
		}
	})
}
