package provider

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizeImageContentParts(t *testing.T) {
	zcodePart := map[string]any{
		"type":      "image",
		"mediaType": "image/png",
		"dataUrl":   "data:image/png;base64,QUJD",
		"source":    map[string]any{"id": "read-image", "kind": "inline", "mimeType": "image/png", "sizeBytes": 3},
	}
	anthropicPart := map[string]any{
		"type":   "image",
		"source": map[string]any{"type": "base64", "media_type": "image/jpeg", "data": "WFla"},
	}
	alreadyPart := map[string]any{
		"type":      "image_url",
		"image_url": map[string]any{"url": "https://example.com/x.png"},
	}
	noDataURL := map[string]any{"type": "image", "source": map[string]any{"kind": "url"}}
	textPart := map[string]any{"type": "text", "text": "hello"}

	in := []any{textPart, zcodePart, anthropicPart, alreadyPart, noDataURL}
	out := normalizeImageContentParts(in)

	if len(out) != len(in) {
		t.Fatalf("part count changed: %d -> %d", len(in), len(out))
	}
	// text untouched
	if !reflect.DeepEqual(out[0], textPart) {
		t.Fatalf("text part altered: %v", out[0])
	}
	// zcode shape -> image_url with its dataUrl
	assertImageURL(t, out[1], "data:image/png;base64,QUJD")
	// anthropic source -> assembled data URL
	assertImageURL(t, out[2], "data:image/jpeg;base64,WFla")
	// already standard -> untouched
	if !reflect.DeepEqual(out[3], alreadyPart) {
		t.Fatalf("standard image_url part altered: %v", out[3])
	}
	// no extractable data -> kept verbatim (upstream error, no fabrication)
	if !reflect.DeepEqual(out[4], noDataURL) {
		t.Fatalf("undata-able part must stay verbatim: %v", out[4])
	}
	// input must not be mutated
	if in[1].(map[string]any)["type"] != "image" {
		t.Fatal("input part mutated")
	}
}

func assertImageURL(t *testing.T, got any, wantURL string) {
	t.Helper()
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("part not a map: %v", got)
	}
	if m["type"] != "image_url" {
		t.Fatalf("type = %v, want image_url", m["type"])
	}
	iu, ok := m["image_url"].(map[string]any)
	if !ok {
		t.Fatalf("image_url block missing: %v", m)
	}
	if iu["url"] != wantURL {
		t.Fatalf("url = %v, want %v", iu["url"], wantURL)
	}
}

func TestEnsureUpstreamMessagesTranslatesImageParts(t *testing.T) {
	msgs := []map[string]any{
		{"role": "system", "content": "be helpful"},
		{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "what color?"},
			map[string]any{"type": "image", "dataUrl": "data:image/png;base64,QUJD", "mediaType": "image/png"},
		}},
		{"role": "tool", "tool_call_id": "call_1", "content": []any{
			map[string]any{"type": "image", "dataUrl": "data:image/png;base64,REFU"},
		}},
	}
	out := EnsureUpstreamMessages(msgs)
	// foldClientInstructions inserts a separate string-content user message
	// for the folded instructions; the original list-content messages must
	// survive verbatim somewhere in the output. Scan all messages.
	var userContent, toolContent any
	for _, m := range out {
		if c, ok := m["content"].([]any); ok {
			for _, p := range c {
				if pm, ok := p.(map[string]any); ok && pm["type"] == "image_url" {
					switch m["role"] {
					case "user":
						userContent = m["content"]
					case "tool":
						toolContent = m["content"]
					}
				}
			}
		}
	}
	if userContent == nil {
		t.Fatal("no user message with image_url parts survived folding")
	}
	assertHasImageURL(t, userContent, "data:image/png;base64,QUJD")
	assertHasImageURL(t, toolContent, "data:image/png;base64,REFU")
}

func assertHasImageURL(t *testing.T, content any, wantURL string) {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parts []map[string]any
	if err := json.Unmarshal(raw, &parts); err != nil {
		t.Fatalf("content not a part list: %s", raw)
	}
	for _, p := range parts {
		if p["type"] == "image_url" {
			if iu, ok := p["image_url"].(map[string]any); ok && iu["url"] == wantURL {
				return
			}
		}
	}
	t.Fatalf("no image_url with %q in %s", wantURL, raw)
}
