package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Sealed commands (room-kit POST /v1/sandboxes/{id}/sealed-exec, AB#417): the
// broker needs no code for them. The room passthrough carries the tail, the body
// and the answer as they are, and copies X-Room-Receipt. These tests hold that:
// a change to the passthrough that rewrites or inspects a sealed exec fails here.

// The shape room_receipts.py sends and answers: base64 and hex only, never a room id.
var sealedExecRequest = []byte(`{"algorithm":"x25519-hkdf-sha256-aes256gcm-v1","binding_sha256":"` +
	strings.Repeat("a", 64) + `","ciphertext_b64":"q83vASNFZ4mrze8BI0Vnia+/+w==","ephemeral_public_b64":"` +
	strings.Repeat("A", 43) + `=","issued_at":1793000000,"nonce_b64":"AAECAwQFBgcICQoL",` +
	`"response_public_b64":"` + strings.Repeat("B", 43) + `=","room_create_receipt_sha256":"` +
	strings.Repeat("c", 64) + `","sandbox_id":"ROOM","schema":"cathedral_sealed_exec_v1","timeout_seconds":30}`)

var sealedExecAnswer = []byte(`{"sealed_response":{"algorithm":"x25519-hkdf-sha256-aes256gcm-v1",` +
	`"ciphertext_b64":"3q2+7w+/AAEC/w==","ephemeral_public_b64":"` + strings.Repeat("C", 43) +
	`=","nonce_b64":"DA0ODxAREhMUFRYX","request_sha256":"` + strings.Repeat("d", 64) +
	`","schema":"cathedral_sealed_exec_response_v1"}}`)

func sealedExecRoom(t *testing.T, tc *testChain) (string, *fakeHotel) {
	t.Helper()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	hotelID, _, _ := strings.Cut(bid, ".")
	f := tc.hotels[hotelID]
	f.mu.Lock()
	f.sealedExecAnswer = sealedExecAnswer
	f.mu.Unlock()
	return bid, f
}

func postSealedExec(t *testing.T, tc *testChain, key, bid string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+bid+"/sealed-exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestSealedExecPassesThroughByteForByte(t *testing.T) {
	tc := newChain(t)
	bid, f := sealedExecRoom(t, tc)
	_, hid, _ := strings.Cut(bid, ".")
	// The room id in the body is the guest's own (the hotel id), as the client seals it.
	body := bytes.Replace(sealedExecRequest, []byte(`"ROOM"`), []byte(`"`+hid+`"`), 1)

	resp, out := postSealedExec(t, tc, "key1", bid, body)

	if resp.StatusCode != 200 {
		t.Fatalf("sealed exec: %d %s", resp.StatusCode, out)
	}
	if !bytes.Equal(out, sealedExecAnswer) {
		t.Fatalf("the answer changed on the way:\n got %s\nwant %s", out, sealedExecAnswer)
	}
	if resp.Header.Get("X-Room-Receipt") != "signed-sealed-exec" {
		t.Fatalf("receipt header: %q", resp.Header.Get("X-Room-Receipt"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sealedExecBodies) != 1 || !bytes.Equal(f.sealedExecBodies[0], body) {
		t.Fatalf("the hotel got another body: %q", f.sealedExecBodies)
	}
	if f.sealedExecPaths[0] != "/v1/sandboxes/"+hid+"/sealed-exec" {
		t.Fatalf("hotel path: %s", f.sealedExecPaths[0])
	}
	// No cmd in the body: the plaintext exec rule (requireExecCmdList) is not asked.
	for _, c := range f.calls {
		if strings.HasSuffix(c, "/exec") {
			t.Fatalf("a plaintext exec reached the hotel: %s", c)
		}
	}
}

func TestSealedExecIsTheOwnersOnly(t *testing.T) {
	tc := newChain(t)
	bid, f := sealedExecRoom(t, tc)

	resp, _ := postSealedExec(t, tc, "key2", bid, sealedExecRequest)

	if resp.StatusCode != 404 {
		t.Fatalf("another guest's sealed exec: %d", resp.StatusCode)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sealedExecBodies) != 0 {
		t.Fatalf("it reached the hotel")
	}
}

// The plaintext exec route is unchanged: a body without cmd is still refused there.
func TestThePlaintextExecRuleStaysOnExec(t *testing.T) {
	tc := newChain(t)
	bid, _ := sealedExecRoom(t, tc)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+bid+"/exec", bytes.NewReader(sealedExecRequest))
	req.Header.Set("Authorization", "Bearer key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("exec without cmd: %d", resp.StatusCode)
	}
}
