package staticlog

import (
	"encoding/json"
	"strings"
	"testing"
)

// An empty audit path must serialize as [] and never as null. Published
// proofs are parsed by third-party verifiers; null is a different shape.
func TestConsistencyFileEmptyAuditPathIsArray(t *testing.T) {
	b, err := json.Marshal(consistencyFile{AuditPath: make([]string, 0)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `"audit_path":[]`) {
		t.Errorf("empty audit path did not marshal as []: %s", got)
	}
	if strings.Contains(got, `"audit_path":null`) {
		t.Errorf("audit path marshalled as null: %s", got)
	}
}
