package provider

import (
	"errors"
	"strings"
	"testing"
)

// resetReader yields `data` and then fails with `reset`, simulating an
// upstream connection torn down mid-response (transport RST after headers).
type resetReader struct {
	data  string
	off   int
	reset error
}

func (r *resetReader) Read(p []byte) (int, error) {
	if r.off < len(r.data) {
		n := copy(p, r.data[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.reset
}

var errUpstreamReset = errors.New("read tcp 10.0.0.2:52352->43.160.158.125:443: wsarecv: An existing connection was forcibly closed by the remote host.")

func TestReadSSEResetBeforeFirstContentMarksReplayable(t *testing.T) {
	c := &Client{}
	// Comment-only bytes (keep-alives) must not count as content.
	body := &resetReader{data: ": keep-alive\n\n", reset: errUpstreamReset}
	_, err := c.readSSE(body, ChatOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stream reset before first content") {
		t.Fatalf("pre-content reset must be marked replayable, got %v", err)
	}
	if !errors.Is(err, errUpstreamReset) {
		t.Fatalf("original error must stay wrapped, got %v", err)
	}
}

func TestReadSSEThinkingOnlyThenResetMarksReplayable(t *testing.T) {
	// Production evidence class: reasoning streamed for minutes, then a hard
	// reset with zero text/tool delivered. Reasoning is auxiliary for agent
	// clients (they consume text + tools), so the replay stays invisible.
	c := &Client{}
	body := &resetReader{
		data:  "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"long thinking...\"}}]}\n\n",
		reset: errUpstreamReset,
	}
	_, err := c.readSSE(body, ChatOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stream reset before first content") {
		t.Fatalf("thinking-only reset must be marked replayable, got %v", err)
	}
}

func TestReadSSEResetAfterFirstFrameNotMarked(t *testing.T) {
	c := &Client{}
	body := &resetReader{
		data:  "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
		reset: errUpstreamReset,
	}
	_, err := c.readSSE(body, ChatOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "stream reset before first content") {
		t.Fatalf("post-content reset must NOT be marked replayable, got %v", err)
	}
	if !errors.Is(err, errUpstreamReset) {
		t.Fatalf("original error must be returned unwrapped, got %v", err)
	}
}
