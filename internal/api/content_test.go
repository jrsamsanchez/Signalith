package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

func TestContentUpdates(t *testing.T) {
	t.Cleanup(func() { detect.UsePacks(nil, nil, "") })
	priv, pub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := content.ParsePrivateKey(priv)
	keys, _ := content.ParseKeys(pub)
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Content = &content.Updater{Dir: filepath.Join(t.TempDir(), "content"), Keys: keys, Library: s.Detections}
	})

	code, body := do(t, ts, "GET", "/api/detections/content", "", true)
	st, _ := body["status"].(map[string]any)
	if code != 200 || st["updated"] != false || st["ready"] != true || body["mode"] != "manual" {
		t.Fatalf("status = %d %v", code, body)
	}

	// A pack rule turned on stays on through an update.
	code, body = do(t, ts, "GET", "/api/detections", "", true)
	var id string
	for _, x := range body["detections"].([]any) {
		if d := x.(map[string]any); d["source"] == "pack" {
			id = d["id"].(string)
			break
		}
	}
	if code, _ := do(t, ts, "POST", "/api/detections/enable", fmt.Sprintf(`{"ids":[%q],"enabled":true}`, id), true); code != 200 {
		t.Fatalf("enable = %d", code)
	}

	data, _, err := content.Build("../detect/packs", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	upload := func(bundle, sig []byte) (int, map[string]any) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if bundle != nil {
			w, _ := mw.CreateFormFile("bundle", "signalith-content.tar.gz")
			w.Write(bundle)
		}
		if sig != nil {
			w, _ := mw.CreateFormFile("signature", "signalith-content.tar.gz.sig")
			w.Write(sig)
		}
		mw.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/api/detections/content/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.SetBasicAuth("admin", "s3cret-pass")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, body := upload(data, nil); code != 400 {
		t.Errorf("no signature = %d %v", code, body)
	}
	bad := bytes.Clone(data)
	bad[100] ^= 1
	if code, body := upload(bad, content.Sign(key, data)); code != 400 {
		t.Errorf("changed bundle = %d %v", code, body)
	}
	code, body = upload(data, content.Sign(key, data))
	st, _ = body["status"].(map[string]any)
	if code != 200 || st["updated"] != true || st["version"] != "20990101000000" {
		t.Fatalf("upload = %d %v", code, body)
	}
	if code, _ := upload(data, content.Sign(key, data)); code != 409 {
		t.Errorf("same again = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/detections/"+id, "", true)
	if code != 200 || body["enabled"] != true {
		t.Errorf("%s after the update = %d %v", id, code, body["enabled"])
	}

	code, body = do(t, ts, "DELETE", "/api/detections/content", "", true)
	if st, _ := body["status"].(map[string]any); code != 200 || st["updated"] != false {
		t.Errorf("remove = %d %v", code, body)
	}
}
