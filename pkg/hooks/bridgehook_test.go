package hooks

import (
	"encoding/base64"
	"testing"

	mccrypto "github.com/kabili207/meshcore-go/core/crypto"
)

func TestComputeChannelHash(t *testing.T) {
	// Test with a known key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	hash := mccrypto.ComputeChannelHash(key)

	// The hash should be consistent
	hash2 := mccrypto.ComputeChannelHash(key)
	if hash != hash2 {
		t.Errorf("ComputeChannelHash not deterministic: got %d then %d", hash, hash2)
	}

	// Different keys should (usually) produce different hashes
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}
	hash3 := mccrypto.ComputeChannelHash(key2)
	if hash == hash3 {
		t.Log("Warning: Different keys produced same hash (collision)")
	}
}

func TestEncryptDecryptGroupMessage(t *testing.T) {
	// Test key (32 bytes)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 0x10)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"short", "Hi"},
		{"medium", "Hello, World!"},
		{"long", "This is a longer message that spans multiple AES blocks to test padding"},
		{"exact_block", "1234567890123456"}, // Exactly 16 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := mccrypto.EncryptGroupMessage([]byte(tt.plaintext), key)
			if err != nil {
				t.Fatalf("EncryptGroupMessage failed: %v", err)
			}

			decrypted, err := mccrypto.DecryptGroupMessage(encrypted, key)
			if err != nil {
				t.Fatalf("DecryptGroupMessage failed: %v", err)
			}

			// Decrypted may have trailing zeros due to block padding
			result := string(decrypted)
			// Trim trailing zeros
			for len(result) > 0 && result[len(result)-1] == 0 {
				result = result[:len(result)-1]
			}

			if result != tt.plaintext {
				t.Errorf("Round-trip failed: got %q, want %q", result, tt.plaintext)
			}
		})
	}
}

func TestEncryptGroupMessageInvalidKey(t *testing.T) {
	plaintext := []byte("test message")

	// Invalid key sizes
	invalidKeys := [][]byte{
		make([]byte, 8),  // Too short
		make([]byte, 24), // 24 bytes - not supported by MeshCore
		make([]byte, 64), // Too long
	}

	for _, key := range invalidKeys {
		_, err := mccrypto.EncryptGroupMessage(plaintext, key)
		if err == nil {
			t.Errorf("EncryptGroupMessage should fail for key size %d", len(key))
		}
	}

	// Valid key sizes
	validKeys := [][]byte{
		make([]byte, 16),
		make([]byte, 32),
	}

	for _, key := range validKeys {
		_, err := mccrypto.EncryptGroupMessage(plaintext, key)
		if err != nil {
			t.Errorf("EncryptGroupMessage should succeed for key size %d: %v", len(key), err)
		}
	}
}

func TestDecryptGroupMessageMACMismatch(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted message
	encrypted, err := mccrypto.EncryptGroupMessage([]byte("test"), key)
	if err != nil {
		t.Fatalf("EncryptGroupMessage failed: %v", err)
	}

	// Corrupt the MAC (first 2 bytes)
	encrypted[0] ^= 0xFF
	encrypted[1] ^= 0xFF

	_, err = mccrypto.DecryptGroupMessage(encrypted, key)
	if err != mccrypto.ErrMACMismatch {
		t.Errorf("Expected ErrMACMismatch, got: %v", err)
	}
}

func TestBuildGrpTxtPlaintext(t *testing.T) {
	timestamp := uint32(1704067200) // 2024-01-01 00:00:00 UTC
	message := "Hello, World!"

	plaintext := mccrypto.BuildGrpTxtPlaintext(timestamp, message)

	// Check length: 4 (timestamp) + 1 (type) + len(message)
	expectedLen := 5 + len(message)
	if len(plaintext) != expectedLen {
		t.Errorf("Plaintext length: got %d, want %d", len(plaintext), expectedLen)
	}

	// Parse it back
	ts, txtType, msg, err := mccrypto.ParseGrpTxtPlaintext(plaintext)
	if err != nil {
		t.Fatalf("ParseGrpTxtPlaintext failed: %v", err)
	}

	if ts != timestamp {
		t.Errorf("Timestamp: got %d, want %d", ts, timestamp)
	}

	if txtType != 0 {
		t.Errorf("TxtType: got %d, want 0", txtType)
	}

	if msg != message {
		t.Errorf("Message: got %q, want %q", msg, message)
	}
}

func TestParseGrpTxtPlaintextTooShort(t *testing.T) {
	_, _, _, err := mccrypto.ParseGrpTxtPlaintext([]byte{1, 2, 3, 4}) // Only 4 bytes
	if err == nil {
		t.Error("Expected error for too-short plaintext")
	}
}

func TestFormatMeshtasticToMeshCore(t *testing.T) {
	tests := []struct {
		sender  string
		message string
		prefix  string
		want    string
	}{
		{"", "Hello", "", "Hello"},
		{"Alice", "Hello", "", "Alice: Hello"},
		{"", "Hello", "[MT] ", "[MT] Hello"},
		{"Bob", "Hi there", "[MT] ", "[MT] Bob: Hi there"},
	}

	for _, tt := range tests {
		got := FormatMeshtasticToMeshCore(tt.sender, tt.message, tt.prefix)
		if got != tt.want {
			t.Errorf("FormatMeshtasticToMeshCore(%q, %q, %q) = %q, want %q",
				tt.sender, tt.message, tt.prefix, got, tt.want)
		}
	}
}

func TestFormatMeshCoreToMeshtastic(t *testing.T) {
	tests := []struct {
		message     string
		prefix      string
		parseSender bool
		wantMsg     string
		wantSender  string
	}{
		{"Hello", "", false, "Hello", ""},
		{"Hello", "[MC] ", false, "[MC] Hello", ""},
		{"Alice: Hello", "", true, "Alice: Hello", "Alice"},
		{"Alice: Hello", "[MC] ", true, "[MC] Alice: Hello", "Alice"},
		{"No colon here", "", true, "No colon here", ""},
	}

	for _, tt := range tests {
		gotMsg, gotSender := FormatMeshCoreToMeshtastic(tt.message, tt.prefix, tt.parseSender)
		if gotMsg != tt.wantMsg {
			t.Errorf("FormatMeshCoreToMeshtastic(%q, %q, %v) msg = %q, want %q",
				tt.message, tt.prefix, tt.parseSender, gotMsg, tt.wantMsg)
		}
		if gotSender != tt.wantSender {
			t.Errorf("FormatMeshCoreToMeshtastic(%q, %q, %v) sender = %q, want %q",
				tt.message, tt.prefix, tt.parseSender, gotSender, tt.wantSender)
		}
	}
}

func TestParseSenderFromMessage(t *testing.T) {
	tests := []struct {
		message       string
		wantSender    string
		wantRemaining string
		wantFound     bool
	}{
		{"Alice: Hello", "Alice", "Hello", true},
		{"Bob: Hi there!", "Bob", "Hi there!", true},
		{"No colon", "", "No colon", false},
		{"Colon:NoSpace", "", "Colon:NoSpace", false},
		{": Empty sender", "", ": Empty sender", false},
		{"VeryLongSenderNameThatExceeds32Characters: msg", "", "VeryLongSenderNameThatExceeds32Characters: msg", false},
		{"A: Single char sender", "A", "Single char sender", true},
	}

	for _, tt := range tests {
		sender, remaining, found := ParseSenderFromMessage(tt.message)
		if sender != tt.wantSender || remaining != tt.wantRemaining || found != tt.wantFound {
			t.Errorf("ParseSenderFromMessage(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.message, sender, remaining, found,
				tt.wantSender, tt.wantRemaining, tt.wantFound)
		}
	}
}

func TestHasBridgePrefix(t *testing.T) {
	tests := []struct {
		message string
		mtPfx   string
		mcPfx   string
		want    bool
	}{
		{"[MT] Hello", "[MT] ", "[MC] ", true},
		{"[MC] Hello", "[MT] ", "[MC] ", true},
		{"Hello", "[MT] ", "[MC] ", false},
		{"Hello", "", "", false},
		{"[MT] Hello", "", "[MC] ", false},
	}

	for _, tt := range tests {
		got := HasBridgePrefix(tt.message, tt.mtPfx, tt.mcPfx)
		if got != tt.want {
			t.Errorf("HasBridgePrefix(%q, %q, %q) = %v, want %v",
				tt.message, tt.mtPfx, tt.mcPfx, got, tt.want)
		}
	}
}

func TestTruncateMessage(t *testing.T) {
	tests := []struct {
		message string
		maxLen  int
		want    string
	}{
		{"Hello", 10, "Hello"},
		{"Hello World", 5, "Hello"},
		{"Hello World", 8, "Hello"},   // Breaks at space
		{"HelloWorld", 5, "Hello"},    // No space, just truncate
		{"A B C D E", 5, "A B"},       // Breaks at last space within limit (index 3)
	}

	for _, tt := range tests {
		got := TruncateMessage(tt.message, tt.maxLen)
		if got != tt.want {
			t.Errorf("TruncateMessage(%q, %d) = %q, want %q",
				tt.message, tt.maxLen, got, tt.want)
		}
	}
}

func TestComputeFingerprint(t *testing.T) {
	fp1 := computeFingerprint("Hello", "LongFast", "meshtastic")
	fp2 := computeFingerprint("Hello", "LongFast", "meshtastic")
	fp3 := computeFingerprint("Hello", "LongFast", "meshcore")
	fp4 := computeFingerprint("Goodbye", "LongFast", "meshtastic")

	if fp1 != fp2 {
		t.Error("Same inputs should produce same fingerprint")
	}

	if fp1 == fp3 {
		t.Error("Different protocol should produce different fingerprint")
	}

	if fp1 == fp4 {
		t.Error("Different message should produce different fingerprint")
	}
}

func TestBridgeHookNodeNameCache(t *testing.T) {
	h := &BridgeHook{
		mtNodeNames: make(map[uint32]string),
		mcNodeNames: make(map[string]string),
	}

	// Test Meshtastic node name caching
	h.updateMeshtasticNodeName(0x12345678, "TestNode")

	if !h.isKnownMeshtasticName("TestNode") {
		t.Error("Expected TestNode to be recognized as Meshtastic node")
	}

	if h.isKnownMeshtasticName("UnknownNode") {
		t.Error("Expected UnknownNode to not be recognized")
	}

	// Test MeshCore node name caching
	h.mcNodeNames["0102030405060708"] = "MCNode"

	if !h.isKnownMeshCoreName("MCNode") {
		t.Error("Expected MCNode to be recognized as MeshCore node")
	}

	if h.isKnownMeshCoreName("UnknownMC") {
		t.Error("Expected UnknownMC to not be recognized")
	}
}

func TestLoopDetectionWithNames(t *testing.T) {
	// Test that messages from known nodes on the other network are detected

	// Scenario: A message "Alice: Hello" comes from MeshCore
	// If "Alice" is a known Meshtastic node, it's a loop
	h := &BridgeHook{
		mtNodeNames: make(map[uint32]string),
		mcNodeNames: make(map[string]string),
	}

	h.mtNodeNames[0xABCDEF12] = "Alice"

	// Parse the message
	sender, _, hasSender := ParseSenderFromMessage("Alice: Hello from the mesh!")

	if !hasSender {
		t.Fatal("Expected to parse sender from message")
	}

	if sender != "Alice" {
		t.Errorf("Expected sender 'Alice', got '%s'", sender)
	}

	// Check if this is a known Meshtastic name (loop detection)
	if !h.isKnownMeshtasticName(sender) {
		t.Error("Expected Alice to be detected as a known Meshtastic node")
	}
}

func TestMCPubKeyToNodeID(t *testing.T) {
	// Test determinism - same pubkey should always produce same NodeID
	pubkey := make([]byte, 32)
	for i := range pubkey {
		pubkey[i] = byte(i + 0x10)
	}

	nodeID1 := MCPubKeyToNodeID(pubkey)
	nodeID2 := MCPubKeyToNodeID(pubkey)

	if nodeID1 != nodeID2 {
		t.Errorf("MCPubKeyToNodeID not deterministic: got %08x then %08x", nodeID1, nodeID2)
	}

	// Different pubkeys should produce different NodeIDs
	pubkey2 := make([]byte, 32)
	for i := range pubkey2 {
		pubkey2[i] = byte(i + 0x20)
	}

	nodeID3 := MCPubKeyToNodeID(pubkey2)
	if nodeID1 == nodeID3 {
		t.Log("Warning: Different pubkeys produced same NodeID (collision)")
	}

	// NodeID should be non-zero for typical pubkeys
	if nodeID1 == 0 {
		t.Error("MCPubKeyToNodeID produced zero NodeID")
	}
}

func TestEncryptDecryptWithBase64Key(t *testing.T) {
	// Test with a real base64-encoded key like would be in config
	keyBase64 := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		t.Fatalf("Failed to decode base64 key: %v", err)
	}

	message := "Test message for encryption"
	plaintext := mccrypto.BuildGrpTxtPlaintext(1234567890, message)

	encrypted, err := mccrypto.EncryptGroupMessage(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptGroupMessage failed: %v", err)
	}

	decrypted, err := mccrypto.DecryptGroupMessage(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptGroupMessage failed: %v", err)
	}

	// Parse decrypted content
	_, _, decMsg, err := mccrypto.ParseGrpTxtPlaintext(decrypted)
	if err != nil {
		t.Fatalf("ParseGrpTxtPlaintext failed: %v", err)
	}

	if decMsg != message {
		t.Errorf("Round-trip failed: got %q, want %q", decMsg, message)
	}
}
