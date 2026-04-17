package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/internal/httputil"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"key": "value"})
	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), `"key":"value"`) {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("got Content-Type %q, want application/json", ct)
	}
}

func TestDecodeJSON(t *testing.T) {
	body := `{"name":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	var out map[string]string
	if err := httputil.DecodeJSON(req, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["name"] != "alice" {
		t.Errorf("got %q, want alice", out["name"])
	}
}
