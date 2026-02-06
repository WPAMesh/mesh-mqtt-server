package codec

import (
	"encoding/binary"
	"testing"
)

func TestParseAdvertPayload(t *testing.T) {
	// Build a minimal valid ADVERT payload
	payload := make([]byte, AdvertMinSize)

	// Set public key (32 bytes)
	for i := 0; i < 32; i++ {
		payload[i] = byte(i)
	}

	// Set timestamp (little endian)
	binary.LittleEndian.PutUint32(payload[32:36], 1704067200) // 2024-01-01 00:00:00 UTC

	// Set signature (64 bytes)
	for i := 0; i < 64; i++ {
		payload[36+i] = byte(i + 100)
	}

	advert, err := ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	// Verify public key
	for i := 0; i < 32; i++ {
		if advert.PubKey[i] != byte(i) {
			t.Errorf("PubKey[%d] = %d, want %d", i, advert.PubKey[i], i)
		}
	}

	// Verify timestamp
	if advert.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", advert.Timestamp, 1704067200)
	}

	// Verify signature
	for i := 0; i < 64; i++ {
		if advert.Signature[i] != byte(i+100) {
			t.Errorf("Signature[%d] = %d, want %d", i, advert.Signature[i], i+100)
		}
	}

	// No appdata
	if advert.AppData != nil {
		t.Error("AppData should be nil for minimal payload")
	}
}

func TestParseAdvertPayloadWithAppData(t *testing.T) {
	// Build ADVERT payload with appdata
	payload := make([]byte, AdvertMinSize+1+4+4+len("TestNode"))

	// Set minimal pubkey/timestamp/signature
	for i := 0; i < 32; i++ {
		payload[i] = byte(i)
	}
	binary.LittleEndian.PutUint32(payload[32:36], 1704067200)
	for i := 0; i < 64; i++ {
		payload[36+i] = 0xAA
	}

	// AppData: flags (chat node + has location + has name)
	offset := AdvertMinSize
	payload[offset] = NodeTypeChat | FlagHasLocation | FlagHasName
	offset++

	// Latitude: 37.7749 * 1_000_000 = 37774900
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 37774900)
	offset += 4

	// Longitude: -122.4194 * 1_000_000 = -122419400
	lonRaw := int32(-122419400)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(lonRaw))
	offset += 4

	// Name
	copy(payload[offset:], "TestNode")

	advert, err := ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if advert.AppData == nil {
		t.Fatal("AppData should not be nil")
	}

	// Check node type
	if advert.AppData.NodeType != NodeTypeChat {
		t.Errorf("NodeType = %d, want %d", advert.AppData.NodeType, NodeTypeChat)
	}

	// Check name
	if advert.AppData.Name != "TestNode" {
		t.Errorf("Name = %s, want TestNode", advert.AppData.Name)
	}

	// Check location
	if advert.AppData.Lat == nil || advert.AppData.Lon == nil {
		t.Fatal("Location should not be nil")
	}

	// Allow small floating point error
	expectedLat := 37.7749
	expectedLon := -122.4194
	if *advert.AppData.Lat < expectedLat-0.0001 || *advert.AppData.Lat > expectedLat+0.0001 {
		t.Errorf("Lat = %f, want ~%f", *advert.AppData.Lat, expectedLat)
	}
	if *advert.AppData.Lon < expectedLon-0.0001 || *advert.AppData.Lon > expectedLon+0.0001 {
		t.Errorf("Lon = %f, want ~%f", *advert.AppData.Lon, expectedLon)
	}
}

func TestParseAdvertPayloadTooShort(t *testing.T) {
	payload := make([]byte, AdvertMinSize-1)
	_, err := ParseAdvertPayload(payload)
	if err == nil {
		t.Error("ParseAdvertPayload() should error on short payload")
	}
}

func TestParseAdvertAppData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantType    uint8
		wantName    string
		wantHasLoc  bool
		wantLat     float64
		wantLon     float64
		wantFeature1 *uint16
		wantFeature2 *uint16
	}{
		{
			name:     "chat node, name only",
			data:     append([]byte{NodeTypeChat | FlagHasName}, []byte("Alice")...),
			wantType: NodeTypeChat,
			wantName: "Alice",
		},
		{
			name:     "repeater, no extras",
			data:     []byte{NodeTypeRepeater},
			wantType: NodeTypeRepeater,
			wantName: "",
		},
		{
			name:       "room with location",
			data:       buildAppDataWithLocation(NodeTypeRoom, 40000000, -74000000),
			wantType:   NodeTypeRoom,
			wantHasLoc: true,
			wantLat:    40.0,
			wantLon:    -74.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appData, err := ParseAdvertAppData(tt.data)
			if err != nil {
				t.Fatalf("ParseAdvertAppData() error = %v", err)
			}

			if appData.NodeType != tt.wantType {
				t.Errorf("NodeType = %d, want %d", appData.NodeType, tt.wantType)
			}
			if appData.Name != tt.wantName {
				t.Errorf("Name = %s, want %s", appData.Name, tt.wantName)
			}
			if appData.HasLocation() != tt.wantHasLoc {
				t.Errorf("HasLocation() = %v, want %v", appData.HasLocation(), tt.wantHasLoc)
			}
			if tt.wantHasLoc {
				if *appData.Lat != tt.wantLat {
					t.Errorf("Lat = %f, want %f", *appData.Lat, tt.wantLat)
				}
				if *appData.Lon != tt.wantLon {
					t.Errorf("Lon = %f, want %f", *appData.Lon, tt.wantLon)
				}
			}
		})
	}
}

func buildAppDataWithLocation(nodeType uint8, lat, lon int32) []byte {
	data := make([]byte, 1+8)
	data[0] = nodeType | FlagHasLocation
	binary.LittleEndian.PutUint32(data[1:5], uint32(lat))
	binary.LittleEndian.PutUint32(data[5:9], uint32(lon))
	return data
}

func TestNodeTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{NodeTypeChat, "chat"},
		{NodeTypeRepeater, "repeater"},
		{NodeTypeRoom, "room"},
		{NodeTypeSensor, "sensor"},
		{0, "unknown"},
		{5, "unknown(5)"},
	}

	for _, tt := range tests {
		if got := NodeTypeName(tt.typ); got != tt.want {
			t.Errorf("NodeTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}
