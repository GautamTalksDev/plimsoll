package site

import (
	"strings"
	"testing"
)

const testHash = "sha256:" + "ab12" + "34567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"

// A static host decodes the request path once before matching a file, so any
// percent-encoding in a generated directory name makes that file unreachable
// and the host answers with its HTML fallback under HTTP 200. Clients then
// hang parsing HTML as JSON. Generated paths must contain no '%'.
func TestSealPathHasNoPercentEncoding(t *testing.T) {
	for _, got := range []string{SealDir(testHash), SealPath(testHash)} {
		if strings.Contains(got, "%") {
			t.Errorf("generated path contains percent-encoding: %q", got)
		}
		if strings.Contains(got, ":") {
			t.Errorf("generated path contains a colon: %q", got)
		}
	}
}

func TestParseSealDirRoundTrips(t *testing.T) {
	if got := ParseSealDir(SealDir(testHash)); got != testHash {
		t.Errorf("round trip: got %q want %q", got, testHash)
	}
	// The canonical digest form must pass through unchanged, because a real
	// HTTP server has already decoded %3A to ':' before we see it.
	if got := ParseSealDir(testHash); got != testHash {
		t.Errorf("canonical form: got %q want %q", got, testHash)
	}
}
