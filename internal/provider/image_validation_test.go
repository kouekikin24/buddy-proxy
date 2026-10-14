package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// dataURL builds a data URL with the given header and raw bytes.
func dataURL(header string, raw []byte) string {
	return "data:" + header + ";base64," + base64.StdEncoding.EncodeToString(raw)
}

func jpegMagicURL() string {
	return dataURL("image/jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0})
}

func gifMagicURL() string {
	return dataURL("image/gif", append([]byte("GIF89a"), 0x00))
}

func webpMagicURL() string {
	raw := append([]byte("RIFF"), 0x10, 0x00, 0x00, 0x00)
	raw = append(raw, []byte("WEBPVP8 ")...)
	return dataURL("image/webp", raw)
}

// g1URL = probe A: image_url carrying base64 that cannot decode at all.
func g1URL() string { return "data:image/png;base64,####not base64!!!!" }

// g2URL = probe B: valid base64 of raw non-image bytes (a client reading a
// non-image file such as a raw dump).
func g2URL() string {
	return dataURL("image/png", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
}

func TestImageDataURLIssue(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string // "" = healthy/pass
	}{
		{"valid png magic", pngDataURL(), ""},
		{"valid jpeg magic", jpegMagicURL(), ""},
		{"valid gif magic", gifMagicURL(), ""},
		{"valid webp magic", webpMagicURL(), ""},
		{"png magic + payload", pngDataURL(1, 2, 3), ""},
		{"base64 without padding tolerated", strings.TrimSuffix(pngDataURL(), "="), ""},
		{"whitespace inside base64 tolerated", "data:image/png;base64,iVBORw0KG go=", ""},
		{"uppercase header tolerated", "DATA:image/png;base64,iVBORw0KGgo=", ""},
		{"probe A undecodable base64", g1URL(), "undecodable base64"},
		{"probe B valid base64 non-image bytes", g2URL(), "magic bytes not an image"},
		{"empty payload", "data:image/png;base64,", "magic bytes not an image"},
		{"too short for any magic", dataURL("image/png", []byte{0x89, 'P'}), "magic bytes not an image"},
		{"missing comma", "data:image/png;base64", "malformed data url"},
		{"non-base64 data url", "data:image/png,abcd", "non-base64 data url"},
		{"remote https url passes through", "https://example.com/x.png", ""},
		{"remote http url passes through", "http://example.com/x.png", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageDataURLIssue(tc.url); got != tc.want {
				t.Fatalf("issue=%q want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeContentPartsStripsBadImages(t *testing.T) {
	badStandard := map[string]any{"type": "image_url", "image_url": map[string]any{"url": g1URL()}}
	g2Standard := map[string]any{"type": "image_url", "image_url": map[string]any{"url": g2URL()}}
	goodStandard := map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}}
	remoteStandard := map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.com/x.png"}}
	badInternal := map[string]any{"type": "image", "dataUrl": g1URL(), "mediaType": "image/png"}
	text := map[string]any{"type": "text", "text": "look at this"}
	placeholder := map[string]any{"type": "text", "text": droppedImagePlaceholder}

	cases := []struct {
		name string
		in   []any
		want any
	}{
		{"bad standard image_url alone collapses to placeholder", []any{badStandard}, droppedImagePlaceholder},
		{"probe B raw bytes stripped same as probe A", []any{g2Standard}, droppedImagePlaceholder},
		{"bad internal-shape image stripped too", []any{badInternal}, droppedImagePlaceholder},
		{"text + bad image collapses to text + placeholder", []any{text, badStandard}, "look at this" + droppedImagePlaceholder},
		{"one placeholder even for several bad images", []any{badStandard, g2Standard}, droppedImagePlaceholder},
		{"bad at position kept inline, good image survives", []any{badStandard, goodStandard}, []any{
			placeholder, goodStandard,
		}},
		{"good images untouched", []any{text, goodStandard, remoteStandard}, []any{
			text, goodStandard, remoteStandard,
		}},
		{"malformed image_url shape kept for loud fail", []any{
			map[string]any{"type": "image_url", "image_url": "not-a-map"},
		}, []any{map[string]any{"type": "image_url", "image_url": "not-a-map"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeContentParts(tc.in)
			switch want := tc.want.(type) {
			case string:
				s, ok := got.(string)
				if !ok || s != want {
					t.Fatalf("got %#v want string %q", got, want)
				}
			case []any:
				g, ok := got.([]any)
				if !ok || !samePartLists(g, want) {
					t.Fatalf("got %#v want %#v", got, want)
				}
			}
		})
	}
	// input parts must not be mutated by stripping
	normalizeContentParts([]any{badStandard})
	if badStandard["type"] != "image_url" {
		t.Fatal("input part mutated")
	}
	iu, _ := badStandard["image_url"].(map[string]any)
	if iu == nil || iu["url"] != g1URL() {
		t.Fatal("input part nested map mutated")
	}
}

func samePartLists(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ja, _ := json.Marshal(a[i])
		jb, _ := json.Marshal(b[i])
		if !bytes.Equal(ja, jb) {
			return false
		}
	}
	return true
}

// TestEnsureUpstreamMessagesStripsUndecodableHistoryImage reproduces the
// The production wire shape: standard image_url parts carrying
// provider-undecodable data. They must not reach upstream; the messages
// survive with placeholder text instead of poisoning every later turn.
func TestEnsureUpstreamMessagesStripsUndecodableHistoryImage(t *testing.T) {
	msgs := []map[string]any{
		{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "check this screenshot"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": g1URL()}},
		}},
		{"role": "assistant", "content": "working on it", "tool_calls": []any{
			map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "Read", "arguments": `{}`}},
		}},
		{"role": "tool", "tool_call_id": "c1", "content": []any{
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": g2URL()}},
		}},
		{"role": "user", "content": []any{
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}},
			map[string]any{"type": "text", "text": "and this one?"},
		}},
	}
	out := EnsureUpstreamMessages(msgs)
	raw, _ := json.Marshal(out)
	s := string(raw)
	if strings.Contains(s, "####not base64") {
		t.Fatalf("probe A poison leaked upstream: %s", s)
	}
	if strings.Contains(s, base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8})) {
		t.Fatalf("probe B poison leaked upstream: %s", s)
	}
	if !strings.Contains(s, droppedImagePlaceholder) {
		t.Fatalf("placeholder missing: %s", s)
	}
	// valid image still forwarded untouched
	assertHasImageURL(t, findContent(out, "user"), pngDataURL())
	// tool message survives (has tool_call_id) with placeholder content
	for _, m := range out {
		if m["role"] == "tool" {
			if c, _ := m["content"].(string); !strings.Contains(c, droppedImagePlaceholder) {
				t.Fatalf("tool message should carry placeholder, got %#v", m["content"])
			}
		}
	}
}

func TestDroppedImageWarns(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	normalizeContentParts([]any{
		map[string]any{"type": "image_url", "image_url": map[string]any{"url": g1URL()}},
	})
	out := buf.String()
	if !strings.Contains(out, "dropped invalid image part") {
		t.Fatalf("WARN missing: %q", out)
	}
	if !strings.Contains(out, `reason="undecodable base64"`) || !strings.Contains(out, "declared_mime=image/png") {
		t.Fatalf("WARN attributes missing: %q", out)
	}
}
