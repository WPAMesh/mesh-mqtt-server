package hooks

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The helpers below replicate meshcore-room-server's observer signing exactly
// (observer/token.go and observer/nonce.go), so these tests cross-check that
// our verifiers accept genuine room-server credentials.

func roomServerJWT(t *testing.T, priv ed25519.PrivateKey, pubKeyHex, audience string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"publicKey": strings.ToUpper(pubKeyHex),
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
	}
	if audience != "" {
		claims["aud"] = audience
	}
	claims["client"] = "meshcore-room-server"
	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := strings.TrimRight(base64.URLEncoding.EncodeToString(payloadJSON), "=")
	message := jwtObserverHeader + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(message))
	return message + "." + hex.EncodeToString(sig)
}

func roomServerNonce(t *testing.T, priv ed25519.PrivateKey, ts time.Time) string {
	t.Helper()
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint64(nonce[0:8], uint64(ts.Unix()))
	if _, err := rand.Read(nonce[8:]); err != nil {
		t.Fatal(err)
	}
	msg := append(append([]byte{}, meshomaticDomainTag...), nonce...)
	sig := ed25519.Sign(priv, msg)
	return "nonce_auth:v1:" + hex.EncodeToString(nonce) + ":" + hex.EncodeToString(sig)
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, hex.EncodeToString(pub)
}

func TestObserverPubKeyFromUsername(t *testing.T) {
	pub, _, hexKey := genKey(t)

	got, err := observerPubKeyFromUsername("v1_" + strings.ToUpper(hexKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("recovered key does not match")
	}

	if _, err := observerPubKeyFromUsername("someuser"); err == nil {
		t.Fatal("expected error for non-observer username")
	}
	if _, err := observerPubKeyFromUsername("v1_zzzz"); err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if _, err := observerPubKeyFromUsername("v1_00ff"); err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestVerifyObserverJWT(t *testing.T) {
	pub, priv, hexKey := genKey(t)
	now := time.Now()

	token := roomServerJWT(t, priv, hexKey, "mqtt.example.com", time.Hour)

	// Valid, no audience requirement.
	if err := verifyObserverJWT(pub, token, "", now); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	// Valid with matching audience (case-insensitive).
	if err := verifyObserverJWT(pub, token, "MQTT.EXAMPLE.COM", now); err != nil {
		t.Fatalf("valid token with matching audience rejected: %v", err)
	}
	// Wrong required audience.
	if err := verifyObserverJWT(pub, token, "other.example.com", now); err == nil {
		t.Fatal("expected audience mismatch error")
	}
	// Expired.
	expired := roomServerJWT(t, priv, hexKey, "", -time.Minute)
	if err := verifyObserverJWT(pub, expired, "", now); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
	// Wrong signing key.
	_, otherPriv, _ := genKey(t)
	forged := roomServerJWT(t, otherPriv, hexKey, "", time.Hour)
	if err := verifyObserverJWT(pub, forged, "", now); err == nil {
		t.Fatal("expected signature verification to fail for wrong key")
	}
	// Tampered payload (signature no longer matches).
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]
	if err := verifyObserverJWT(pub, tampered, "", now); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestVerifyObserverNonce(t *testing.T) {
	pub, priv, _ := genKey(t)
	now := time.Now()

	pw := roomServerNonce(t, priv, now)
	if err := verifyObserverNonce(pub, pw, now); err != nil {
		t.Fatalf("valid nonce rejected: %v", err)
	}

	// Stale timestamp beyond skew.
	stale := roomServerNonce(t, priv, now.Add(-10*time.Minute))
	if err := verifyObserverNonce(pub, stale, now); err == nil {
		t.Fatal("expected stale nonce to be rejected")
	}

	// Wrong key.
	_, otherPriv, _ := genKey(t)
	forged := roomServerNonce(t, otherPriv, now)
	if err := verifyObserverNonce(pub, forged, now); err == nil {
		t.Fatal("expected forged nonce to be rejected")
	}

	// Malformed.
	if err := verifyObserverNonce(pub, "nonce_auth:v2:abcd:ef01", now); err == nil {
		t.Fatal("expected malformed nonce to be rejected")
	}
}

func TestVerifyObserverPasswordDispatch(t *testing.T) {
	pub, priv, hexKey := genKey(t)
	now := time.Now()

	jwt := roomServerJWT(t, priv, hexKey, "", time.Hour)
	if err := verifyObserverPassword(pub, jwt, "", now); err != nil {
		t.Fatalf("JWT path failed: %v", err)
	}

	nonce := roomServerNonce(t, priv, now)
	if err := verifyObserverPassword(pub, nonce, "", now); err != nil {
		t.Fatalf("nonce path failed: %v", err)
	}
}
