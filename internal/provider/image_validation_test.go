package provider

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"log/slog"
	"strings"
	"testing"
)

// dataURL builds a data URL with the given header and raw bytes.
func dataURL(header string, raw []byte) string {
	return "data:" + header + ";base64," + base64.StdEncoding.EncodeToString(raw)
}

func jpegMagicURL() string {
	raw, err := base64.StdEncoding.DecodeString(validJPEG1x1)
	if err != nil {
		panic(err)
	}
	return dataURL("image/jpeg", raw)
}

// truncatedJPEGURL: valid SOI header, body cut short - the strict
// decoders must reject it.
func truncatedJPEGURL() string {
	raw, _ := base64.StdEncoding.DecodeString(validJPEG1x1)
	return dataURL("image/jpeg", raw[:len(raw)/2])
}

func gifMagicURL() string {
	im := image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.White})
	im.Set(0, 0, color.White)
	var buf bytes.Buffer
	if err := gif.Encode(&buf, im, nil); err != nil {
		panic(err)
	}
	return dataURL("image/gif", buf.Bytes())
}

// pngChunk assembles one PNG chunk with correct CRC.
func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc.Sum32())
	return b.Bytes()
}

// bombPNGDataURL builds a "decompression bomb" shape: an IHDR lying w x h
// with only a few dozen IDAT bytes. Go decoders reserve pixels for the
// declared dimensions first (20000x20000 -> 1.5GB), so the autopsy itself
// would die first - the pixel-budget gate must skip the local decode and
// pass it through (issue "").
func bombPNGDataURL(w, h int) string {
	var ihdr bytes.Buffer
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(w))
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(h))
	ihdr.Write([]byte{8, 6, 0, 0, 0})
	var idat bytes.Buffer
	zw := zlib.NewWriter(&idat)
	_, _ = zw.Write([]byte{0, 0, 0, 0})
	_ = zw.Close()
	var buf bytes.Buffer
	buf.WriteString("\x89PNG\r\n\x1a\n")
	buf.Write(pngChunk("IHDR", ihdr.Bytes()))
	buf.Write(pngChunk("IDAT", idat.Bytes()))
	buf.Write(pngChunk("IEND", nil))
	return dataURL("image/png", buf.Bytes())
}

// poisonPNGDataURL builds the same shape as the production poison: an
// IHDR declaring 900x360 RGBA, valid signature and CRCs for every
// chunk, while the IDAT decompresses to only 1/3 of the declared
// pixel count (300px rows). The magic-only check passes it; the
// full-decode check must catch it.
func poisonPNGDataURL() string {
	var ihdr bytes.Buffer
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(900))
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(360))
	ihdr.Write([]byte{8, 6, 0, 0, 0})
	var rows []byte
	for y := 0; y < 360; y++ {
		rows = append(rows, 0)
		rows = append(rows, make([]byte, 1200)...) // 300 px, not 900
	}
	var idat bytes.Buffer
	zw := zlib.NewWriter(&idat)
	_, _ = zw.Write(rows)
	_ = zw.Close()
	var pngBuf bytes.Buffer
	pngBuf.WriteString("\x89PNG\r\n\x1a\n")
	pngBuf.Write(pngChunk("IHDR", ihdr.Bytes()))
	pngBuf.Write(pngChunk("IDAT", idat.Bytes()))
	pngBuf.Write(pngChunk("IEND", nil))
	return dataURL("image/png", pngBuf.Bytes())
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
		{"base64 without padding tolerated", strings.TrimRight(pngDataURL(), "="), ""},
		{"whitespace inside base64 tolerated", func() string {
			u := pngDataURL()
			i := strings.Index(u, ",")
			h, b := u[:i+1], u[i+1:]
			m := len(b) / 2
			return h + b[:m] + " " + b[m:]
		}(), ""},
		{"uppercase header tolerated", strings.Replace(pngDataURL(), "data:", "DATA:", 1), ""},
		{"probe A undecodable base64", g1URL(), "undecodable base64"},
		{"probe B valid base64 non-image bytes", g2URL(), "magic bytes not an image"},
		{"empty payload", "data:image/png;base64,", "magic bytes not an image"},
		{"too short for any magic", dataURL("image/png", []byte{0x89, 'P'}), "magic bytes not an image"},
		{"header-valid pixel-shortage poison (production shape)", poisonPNGDataURL(), "undecodable image body"},
		{"truncated jpeg body", truncatedJPEGURL(), "undecodable image body"},
		{"decompression bomb passes unautopsied (pixel-budget gate)", bombPNGDataURL(20000, 20000), ""},
		{"in-budget broken png still caught (gate no weakening)", bombPNGDataURL(4000, 3000), "undecodable image body"},
		{"extreme lying dims rejected without panic (overflow-safe gate)", bombPNGDataURL(0x7FFFFFFF, 0x7FFFFFFF), "undecodable image body"},
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
	poisonStandard := map[string]any{"type": "image_url", "image_url": map[string]any{"url": poisonPNGDataURL()}}
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
		{"header-valid pixel-shortage poison stripped (full decode)", []any{poisonStandard}, droppedImagePlaceholder},
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

func TestStripImagesForReplay(t *testing.T) {
	msgs := []map[string]any{
		{"role": "system", "content": "keep"},
		{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "look at this"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}},
		}},
		{"role": "assistant", "content": "called", "tool_calls": []any{map[string]any{"id": "c1", "type": "function"}}},
		{"role": "tool", "tool_call_id": "c1", "content": []any{
			map[string]any{"type": "image", "dataUrl": pngDataURL()},
		}},
	}
	out, changed := StripImagesForReplay(msgs)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if out[0]["content"] != "keep" {
		t.Fatal("string content must pass through")
	}
	// user message: text kept, image replaced by one placeholder, no image part survives
	raw, _ := json.Marshal(out[1]["content"])
	s := string(raw)
	if strings.Contains(s, "image_url") || strings.Contains(s, "data:image") {
		t.Fatalf("image survived strip: %s", s)
	}
	if !strings.Contains(s, "look at this") || !strings.Contains(s, droppedImagePlaceholder) {
		t.Fatalf("placeholder/text missing: %s", s)
	}
	// tool message: image-only content collapses to the placeholder part,
	// pairing intact (normalizeContentParts will fold it to a string on send)
	if parts, ok := out[3]["content"].([]any); !ok || len(parts) != 1 {
		t.Fatalf("image-only tool message should hold one placeholder part, got %#v", out[3]["content"])
	} else if m, _ := parts[0].(map[string]any); m == nil || m["text"] != droppedImagePlaceholder {
		t.Fatalf("placeholder part wrong: %#v", parts[0])
	}
	if out[3]["tool_call_id"] != "c1" || len(out[2]["tool_calls"].([]any)) != 1 {
		t.Fatal("tool pairing must survive strip")
	}
	// inputs must not be mutated
	if _, ok := msgs[1]["content"].([]any); !ok {
		t.Fatal("input messages mutated")
	}
	// no images => changed=false, messages passed through
	out2, changed2 := StripImagesForReplay([]map[string]any{{"role": "user", "content": "plain"}})
	if changed2 || out2[0]["content"] != "plain" {
		t.Fatal("imageless request must be a no-op")
	}
}

func TestOverPixelBudget(t *testing.T) {
	// Extreme lying dimensions must not wrap the product past the gate.
	if !overPixelBudget(0x7FFFFFFF, 0x7FFFFFFF) {
		t.Fatal("max-int32 dims must exceed the pixel budget")
	}
	if !overPixelBudget(20000, 20000) {
		t.Fatal("400M declared pixels must exceed the budget")
	}
	if overPixelBudget(4000, 3000) {
		t.Fatal("12M pixels must stay within the budget (no gate weakening)")
	}
}
