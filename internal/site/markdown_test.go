package site

import (
	"strings"
	"testing"
)

// The spec is CC0 and trusted, but this renderer emits HTML from a file on
// disk. Every construct must escape its input before any tag is added, or a
// future caller pointing it at untrusted Markdown introduces XSS.
func TestRenderMarkdownSafeEscapesEverything(t *testing.T) {
	cases := []string{
		`<script>alert(1)</script>`,
		`# <script>alert(1)</script>`,
		`- <img src=x onerror=alert(1)>`,
		"| <script>a</script> | b |",
		"**<script>a</script>**",
		"`<script>a</script>`",
		"```\n<script>alert(1)</script>\n```",
		`<a href="javascript:alert(1)">x</a>`,
	}
	for _, in := range cases {
		got := string(renderMarkdownSafe(in))
		if strings.Contains(got, "<script>") {
			t.Errorf("unescaped script tag for %q -> %s", in, got)
		}
		if strings.Contains(got, "onerror=") && !strings.Contains(got, "&lt;img") {
			t.Errorf("unescaped attribute for %q -> %s", in, got)
		}
		if strings.Contains(got, "javascript:") && !strings.Contains(got, "&lt;a") {
			t.Errorf("unescaped anchor for %q -> %s", in, got)
		}
	}
}

func TestRenderMarkdownSafeRendersConstructs(t *testing.T) {
	for in, want := range map[string]string{
		"**Version:** prereg-v1": "<strong>Version:</strong>",
		"`plimsoll-canon-v1`":    "<code>plimsoll-canon-v1</code>",
		"## Heading":             "<h2>Heading</h2>",
		"- item":                 "<li>item</li>",
		"| a | b |":              "<th>a</th>",
	} {
		if got := string(renderMarkdownSafe(in)); !strings.Contains(got, want) {
			t.Errorf("%q did not produce %q, got %s", in, want, got)
		}
	}
	// An unmatched delimiter stays literal rather than swallowing the rest.
	if got := string(renderMarkdownSafe("a ** b")); !strings.Contains(got, "**") {
		t.Errorf("unmatched delimiter was consumed: %s", got)
	}
}
