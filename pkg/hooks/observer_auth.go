package hooks

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// observerUserPrefix is the MQTT username prefix used by observer clients.
// The remainder of the username is the uppercase hex Ed25519 public key.
const observerUserPrefix = "v1_"

// jwtObserverHeader is the static base64url header used by observer JWTs.
// Decoded: {"alg":"Ed25519","typ":"JWT"}. Matches the room server token format.
const jwtObserverHeader = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0"

// meshomaticDomainTag is prepended to the nonce before signing. Must match the
// room server's tag exactly; a mismatch causes verification to fail silently.
var meshomaticDomainTag = []byte("meshomatic-mqtt-v1\x00")

// nonceTimeSkew is the maximum allowed difference between the nonce timestamp
// and now for nonce-based auth.
const nonceTimeSkew = 120 * time.Second

// isObserverUsername reports whether the username follows the observer scheme.
func isObserverUsername(user string) bool {
	return strings.HasPrefix(user, observerUserPrefix)
}

// observerPubKeyFromUsername extracts the Ed25519 public key from a "v1_<HEX>"
// username. The hex is case-insensitive.
func observerPubKeyFromUsername(user string) (ed25519.PublicKey, error) {
	if !isObserverUsername(user) {
		return nil, errors.New("username is not an observer username")
	}
	keyHex := user[len(observerUserPrefix):]
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid observer public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("observer public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// verifyObserverPassword authenticates an observer client. It accepts either a
// nonce_auth password (MeshOMatic style) or an Ed25519-signed JWT (letsmesh
// style), verifying the signature against pubKey. requireAudience, when
// non-empty, is enforced against the JWT "aud" claim. It returns nil on success.
func verifyObserverPassword(pubKey ed25519.PublicKey, password, requireAudience string, now time.Time) error {
	if strings.HasPrefix(password, "nonce_auth:") {
		return verifyObserverNonce(pubKey, password, now)
	}
	return verifyObserverJWT(pubKey, password, requireAudience, now)
}

// verifyObserverNonce verifies a "nonce_auth:v1:<nonce_hex>:<sig_hex>" password.
// The signature covers meshomaticDomainTag || nonce, where the nonce is
// BE uint64(epoch seconds) || 16 random bytes. The timestamp must be within
// nonceTimeSkew of now.
func verifyObserverNonce(pubKey ed25519.PublicKey, password string, now time.Time) error {
	parts := strings.Split(password, ":")
	if len(parts) != 4 || parts[0] != "nonce_auth" || parts[1] != "v1" {
		return errors.New("malformed nonce_auth password")
	}

	nonce, err := hex.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != 24 {
		return fmt.Errorf("nonce is %d bytes, want 24", len(nonce))
	}
	sig, err := hex.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("invalid nonce signature hex: %w", err)
	}

	msg := append(append([]byte{}, meshomaticDomainTag...), nonce...)
	if !ed25519.Verify(pubKey, msg, sig) {
		return errors.New("nonce signature verification failed")
	}

	ts := int64(binary.BigEndian.Uint64(nonce[0:8]))
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > nonceTimeSkew {
		return fmt.Errorf("nonce timestamp outside allowed skew (%ds)", skew)
	}
	return nil
}

// observerJWTClaims are the claims verified from an observer JWT.
type observerJWTClaims struct {
	PublicKey string `json:"publicKey"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	Expires   int64  `json:"exp"`
}

// verifyObserverJWT verifies an "<header>.<payload>.<sigHex>" observer token.
// The signature is Ed25519 over "header.payload" and hex-encoded (not
// base64url). The payload's "publicKey" claim must match pubKey, "exp" must be
// in the future, and, when requireAudience is set, "aud" must match it.
func verifyObserverJWT(pubKey ed25519.PublicKey, token, requireAudience string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed JWT")
	}
	if parts[0] != jwtObserverHeader {
		return errors.New("unexpected JWT header")
	}

	sig, err := hex.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid JWT signature hex: %w", err)
	}

	message := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(message), sig) {
		return errors.New("JWT signature verification failed")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	var claims observerJWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("invalid JWT payload: %w", err)
	}

	// The claimed key must match the key that signed the token (from username).
	claimedKey, err := hex.DecodeString(claims.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid publicKey claim: %w", err)
	}
	if !ed25519.PublicKey(claimedKey).Equal(pubKey) {
		return errors.New("JWT publicKey claim does not match username key")
	}

	if claims.Expires != 0 && now.Unix() >= claims.Expires {
		return errors.New("JWT expired")
	}

	if requireAudience != "" && !strings.EqualFold(claims.Audience, requireAudience) {
		return fmt.Errorf("JWT audience %q does not match required %q", claims.Audience, requireAudience)
	}
	return nil
}
