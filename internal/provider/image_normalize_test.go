package provider

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// pngDataURL produces a data URL with a real PNG magic header (the egress
// autopsy only passes legitimate images).
func pngDataURL(body ...byte) string {
	full := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, body...)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(full)
}

func TestNormalizeContentParts(t *testing.T) {
	zcodeImage := map[string]any{
		"type": "image", "mediaType": "image/png",
		"dataUrl": pngDataURL(),
		"source":  map[string]any{"id": "read-image", "kind": "inline"},
	}
	anthropicImage := map[string]any{
		"type":   "image",
		"source": map[string]any{"type": "base64", "media_type": "image/jpeg", "data": "/9j/"},
	}
	alreadyImage := map[string]any{
		"type":      "image_url",
		"image_url": map[string]any{"url": "https://example.com/x.png"},
	}
	noDataImage := map[string]any{"type": "image", "source": map[string]any{"kind": "url"}}
	reasoning := map[string]any{"type": "reasoning", "text": "deep thoughts"}
	text := map[string]any{"type": "text", "text": "hello"}
	unknown := map[string]any{"type": "audio", "data": "x"}

	cases := []struct {
		name string
		in   []any
		want any // string => expect full equality; []any => element-wise
	}{
		{"reasoning+text collapses to string", []any{reasoning, text}, "hello"},
		{"reasoning-only becomes empty string", []any{reasoning}, ""},
		{"image translated, text kept, stays structured", []any{text, zcodeImage}, []any{
			text,
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}},
		}},
		{"anthropic source assembled", []any{anthropicImage}, []any{
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/jpeg;base64,/9j/"}},
		}},
		{"standard image untouched + reasoning dropped", []any{reasoning, alreadyImage}, []any{alreadyImage}},
		{"no-data image kept verbatim (no fabrication)", []any{noDataImage}, []any{noDataImage}},
		{"unknown type preserved for loud upstream error", []any{text, unknown}, []any{text, unknown}},
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
				if !ok || !reflect.DeepEqual(g, want) {
					t.Fatalf("got %#v want %#v", got, want)
				}
			}
		})
	}
	// input must not be mutated
	in := []any{reasoning, zcodeImage}
	normalizeContentParts(in)
	if in[0].(map[string]any)["type"] != "reasoning" || in[1].(map[string]any)["type"] != "image" {
		t.Fatal("input parts mutated")
	}
}

func TestEnsureUpstreamMessagesStripsReasoningAndTranslatesImages(t *testing.T) {
	msgs := []map[string]any{
		{"role": "system", "content": "be helpful"},
		{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "what color?"},
			map[string]any{"type": "image", "dataUrl": pngDataURL(), "mediaType": "image/png"},
		}},
		{"role": "assistant", "content": []any{
			map[string]any{"type": "reasoning", "text": "pondering"},
			map[string]any{"type": "text", "text": "pink"},
		}},
		{"role": "tool", "tool_call_id": "call_1", "content": []any{
			map[string]any{"type": "image", "dataUrl": pngDataURL('A')},
		}},
	}
	out := EnsureUpstreamMessages(msgs)
	raw, _ := json.Marshal(out)
	s := string(raw)
	if strings.Contains(s, `"reasoning"`) {
		t.Fatalf("reasoning survived normalization: %s", s)
	}
	// assistant pure reasoning+text collapsed to string "pink"
	for _, m := range out {
		if m["role"] == "assistant" && m["content"] != "pink" {
			t.Fatalf("assistant should collapse to string, got %#v", m["content"])
		}
	}
	assertHasImageURL(t, findContent(out, "user"), pngDataURL())
	assertHasImageURL(t, findContent(out, "tool"), pngDataURL('A'))
}

func TestEnsureUpstreamMessagesAdoptsCamelCaseKeys(t *testing.T) {
	msgs := []map[string]any{
		{"role": "user", "content": "run it"},
		{"role": "assistant", "content": "", "toolCalls": []any{
			map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "Bash", "arguments": "{}"}},
		}},
		{"role": "tool", "toolCallId": "c1", "toolName": "Bash", "content": "done"},
	}
	out := EnsureUpstreamMessages(msgs)
	var assistant, tool map[string]any
	for _, m := range out {
		switch m["role"] {
		case "assistant":
			assistant = m
		case "tool":
			tool = m
		}
	}
	if assistant == nil || len(asAnySlice(assistant["tool_calls"])) != 1 {
		t.Fatalf("camel toolCalls not adopted: %#v", assistant)
	}
	if tool == nil || tool["tool_call_id"] != "c1" || tool["name"] != "Bash" {
		t.Fatalf("camel toolCallId/toolName not adopted: %#v", tool)
	}
}

func findContent(out []map[string]any, role string) any {
	for _, m := range out {
		if m["role"] == role {
			if _, isStr := m["content"].(string); isStr {
				continue
			}
			return m["content"]
		}
	}
	return nil
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
