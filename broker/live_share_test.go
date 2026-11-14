package main

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func noRedirect() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mintShare(t *testing.T, tc *testChain, key string, body any) map[string]any {
	t.Helper()
	code, doc := tc.call(t, key, "POST", "/v1/live/shares", body)
	if code != 201 {
		t.Fatalf("mint: %d %v", code, doc)
	}
	return doc
}

// openShare follows a share link and returns the cookie it sets.
func openShare(t *testing.T, tc *testChain, link string) *http.Cookie {
	t.Helper()
	resp, err := noRedirect().Get(tc.srv.URL + link)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || len(resp.Cookies()) != 1 {
		t.Fatalf("open share: %d %v", resp.StatusCode, resp.Header)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "share=") {
		t.Fatalf("redirect keeps the token: %s", loc)
	}
	return resp.Cookies()[0]
}

func getWith(t *testing.T, tc *testChain, path string, c *http.Cookie) int {
	t.Helper()
	req, _ := http.NewRequest("GET", tc.srv.URL+path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestLiveShareLinkOpensTheGuestView(t *testing.T) {
	tc := newChain(t)
	doc := mintShare(t, tc, "key1", map[string]any{"ttl_s": 600, "label": "scale run 1"})
	link, _ := doc["url"].(string)
	if !strings.HasPrefix(link, "/g1/live?share=bvs_") || doc["label"] != "scale run 1" || doc["id"] == nil {
		t.Fatalf("mint doc: %v", doc)
	}
	c := openShare(t, tc, link)
	if c.Name != "bvs_g1" || c.Path != "/g1/" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.MaxAge < 1 || c.MaxAge > 600 {
		t.Fatalf("cookie: %+v", c)
	}
	if code := getWith(t, tc, "/g1/live", c); code != 200 {
		t.Fatalf("page with share cookie: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", tc.srv.URL+"/g1/live/events", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	if resp.StatusCode != 200 || !strings.Contains(line, `"guest":"g1"`) {
		t.Fatalf("events: %d %q", resp.StatusCode, line)
	}
	// Without the cookie the page is still closed.
	if code := getWith(t, tc, "/g1/live", nil); code != 401 {
		t.Fatalf("no cookie: %d", code)
	}
}

func TestLiveShareWorksForAGuestWithoutAViewToken(t *testing.T) {
	tc := newChain(t) // g2 has no view token
	if code := getWith(t, tc, "/g2/live", nil); code != 401 {
		t.Fatalf("g2 before: %d", code)
	}
	doc := mintShare(t, tc, "key2", nil)
	c := openShare(t, tc, doc["url"].(string))
	if code := getWith(t, tc, "/g2/live", c); code != 200 {
		t.Fatalf("g2 with share: %d", code)
	}
	exp, err := time.Parse(time.RFC3339, doc["expires_at"].(string))
	if err != nil || exp.Sub(time.Now()) < 3*time.Hour+59*time.Minute || exp.Sub(time.Now()) > 4*time.Hour+time.Minute {
		t.Fatalf("default ttl: %v %v", doc["expires_at"], err)
	}
}

func TestLiveShareForOneGuestDoesNotOpenAnother(t *testing.T) {
	tc := newChain(t)
	doc := mintShare(t, tc, "key1", nil)
	token := strings.TrimPrefix(doc["url"].(string), "/g1/live?share=")
	if code := getWith(t, tc, "/g2/live?share="+token, nil); code != 401 {
		t.Fatalf("g1 link on g2: %d", code)
	}
	if code := getWith(t, tc, "/g2/live", &http.Cookie{Name: "bvs_g2", Value: token}); code != 401 {
		t.Fatalf("g1 token in a g2 cookie: %d", code)
	}
	// A share token is not a view token either.
	if code := getWith(t, tc, "/g1/live", &http.Cookie{Name: "bv_g1", Value: token}); code != 401 {
		t.Fatalf("share token as view cookie: %d", code)
	}
}

func TestLiveShareRevokeClosesTheViewAndTheStream(t *testing.T) {
	tc := newChain(t)
	doc := mintShare(t, tc, "key1", map[string]any{"label": "demo"})
	c := openShare(t, tc, doc["url"].(string))
	id := doc["id"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", tc.srv.URL+"/g1/live/events", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rd := bufio.NewReader(resp.Body)
	if line, _ := rd.ReadString('\n'); !strings.HasPrefix(line, "data: ") {
		t.Fatalf("first event: %q", line)
	}

	// Another guest cannot revoke it.
	if code, _ := tc.call(t, "key2", "DELETE", "/v1/live/shares/"+id, nil); code != 404 {
		t.Fatalf("g2 revoke: %d", code)
	}
	if code, _ := tc.call(t, "key1", "DELETE", "/v1/live/shares/"+id, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	// The open stream ends (EOF) instead of running on.
	for {
		_, err := rd.ReadString('\n')
		if err != nil {
			if ctx.Err() != nil {
				t.Fatal("stream outlived the revoke")
			}
			break
		}
	}
	if code := getWith(t, tc, "/g1/live", c); code != 401 {
		t.Fatalf("page after revoke: %d", code)
	}
	if code, list := tc.call(t, "key1", "GET", "/v1/live/shares", nil); code != 200 || len(list["shares"].([]any)) != 0 {
		t.Fatalf("list after revoke: %d %v", code, list)
	}
}

func TestLiveShareExpires(t *testing.T) {
	tc := newChain(t)
	doc := mintShare(t, tc, "key1", map[string]any{"ttl_s": 60})
	c := openShare(t, tc, doc["url"].(string))
	tc.b.mu.Lock()
	for _, s := range tc.b.shares {
		s.Expires = time.Now().Add(-time.Second)
	}
	tc.b.mu.Unlock()
	req, _ := http.NewRequest("GET", tc.srv.URL+"/g1/live", nil)
	req.AddCookie(c)
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(string(buf[:n]), "share link has ended") {
		t.Fatalf("expired: %d %s", resp.StatusCode, buf[:n])
	}
	if code := getWith(t, tc, doc["url"].(string), nil); code != 401 {
		t.Fatalf("expired link: %d", code)
	}
}

func TestLiveShareListValidationAndCap(t *testing.T) {
	tc := newChain(t)
	for _, body := range []any{
		map[string]any{"ttl_s": 0},
		map[string]any{"ttl_s": 59},
		map[string]any{"ttl_s": 604801},
		map[string]any{"label": strings.Repeat("x", 81)},
		map[string]any{"label": "a\nb"},
		map[string]any{"other": 1},
	} {
		if code, _ := tc.call(t, "key1", "POST", "/v1/live/shares", body); code != 400 {
			t.Fatalf("%v: %d", body, code)
		}
	}
	if code, _ := tc.call(t, "nope", "POST", "/v1/live/shares", nil); code != 401 {
		t.Fatalf("unknown key: %d", code)
	}
	for i := 0; i < liveShareMaxActive; i++ {
		mintShare(t, tc, "key1", nil)
	}
	if code, _ := tc.call(t, "key1", "POST", "/v1/live/shares", nil); code != 429 {
		t.Fatalf("over the cap: %d", code)
	}
	mintShare(t, tc, "key2", nil) // the cap is per guest
	code, list := tc.call(t, "key1", "GET", "/v1/live/shares", nil)
	shares, _ := list["shares"].([]any)
	if code != 200 || len(shares) != liveShareMaxActive {
		t.Fatalf("list: %d %d", code, len(shares))
	}
	for _, s := range shares {
		m := s.(map[string]any)
		if _, ok := m["url"]; ok {
			t.Fatalf("list leaks the link: %v", m)
		}
		for _, v := range m {
			if str, ok := v.(string); ok && strings.HasPrefix(str, "bvs_") {
				t.Fatalf("list leaks a token: %v", m)
			}
		}
	}
}
