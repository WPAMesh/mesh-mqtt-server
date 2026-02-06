package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Advert payload sizes
	AdvertPubKeySize    = 32
	AdvertTimestampSize = 4
	AdvertSignatureSize = 64
	AdvertMinSize       = AdvertPubKeySize + AdvertTimestampSize + AdvertSignatureSize // 100 bytes

	// AppData flags - node types (lower 4 bits)
	NodeTypeChat     = 0x01
	NodeTypeRepeater = 0x02
	NodeTypeRoom     = 0x03
	NodeTypeSensor   = 0x04

	// AppData flags - presence flags (upper 4 bits)
	FlagHasLocation = 0x10
	FlagHasFeature1 = 0x20
	FlagHasFeature2 = 0x40
	FlagHasName     = 0x80

	// Coordinate scale factor (lat/lon stored as int32 * 1_000_000)
	CoordScale = 1_000_000.0
)

var (
	ErrAdvertTooShort   = errors.New("advert payload too short")
	ErrAppDataTooShort  = errors.New("appdata too short")
	ErrInvalidNodeType  = errors.New("invalid node type")
)

// AdvertPayload represents a parsed node advertisement payload.
type AdvertPayload struct {
	PubKey    [32]byte
	Timestamp uint32
	Signature [64]byte
	AppData   *AdvertAppData
}

// AdvertAppData represents the optional application data in an advertisement.
type AdvertAppData struct {
	Flags    uint8
	NodeType uint8    // Lower 4 bits of flags: chat, repeater, room, sensor
	Name     string   // Node name (if FlagHasName set)
	Lat      *float64 // Latitude in decimal degrees (if FlagHasLocation set)
	Lon      *float64 // Longitude in decimal degrees (if FlagHasLocation set)
	Feature1 *uint16  // Reserved (if FlagHasFeature1 set)
	Feature2 *uint16  // Reserved (if FlagHasFeature2 set)
}

// ParseAdvertPayload parses an ADVERT payload into its components.
func ParseAdvertPayload(data []byte) (*AdvertPayload, error) {
	if len(data) < AdvertMinSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrAdvertTooShort, AdvertMinSize, len(data))
	}

	advert := &AdvertPayload{}

	// Public key (32 bytes)
	copy(advert.PubKey[:], data[0:32])

	// Timestamp (4 bytes, little endian per docs)
	advert.Timestamp = binary.LittleEndian.Uint32(data[32:36])

	// Signature (64 bytes)
	copy(advert.Signature[:], data[36:100])

	// Parse optional appdata if present
	if len(data) > AdvertMinSize {
		appData, err := ParseAdvertAppData(data[AdvertMinSize:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse appdata: %w", err)
		}
		advert.AppData = appData
	}

	return advert, nil
}

// ParseAdvertAppData parses the optional application data from an advertisement.
func ParseAdvertAppData(data []byte) (*AdvertAppData, error) {
	if len(data) < 1 {
		return nil, ErrAppDataTooShort
	}

	appData := &AdvertAppData{
		Flags:    data[0],
		NodeType: data[0] & 0x0F, // Lower 4 bits
	}

	offset := 1

	// Parse optional location (8 bytes: lat + lon as int32 little endian)
	if appData.Flags&FlagHasLocation != 0 {
		if len(data) < offset+8 {
			return nil, fmt.Errorf("%w: expected location data", ErrAppDataTooShort)
		}
		latRaw := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		lonRaw := int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		lat := float64(latRaw) / CoordScale
		lon := float64(lonRaw) / CoordScale
		appData.Lat = &lat
		appData.Lon = &lon
		offset += 8
	}

	// Parse optional feature1 (2 bytes, little endian)
	if appData.Flags&FlagHasFeature1 != 0 {
		if len(data) < offset+2 {
			return nil, fmt.Errorf("%w: expected feature1 data", ErrAppDataTooShort)
		}
		f1 := binary.LittleEndian.Uint16(data[offset : offset+2])
		appData.Feature1 = &f1
		offset += 2
	}

	// Parse optional feature2 (2 bytes, little endian)
	if appData.Flags&FlagHasFeature2 != 0 {
		if len(data) < offset+2 {
			return nil, fmt.Errorf("%w: expected feature2 data", ErrAppDataTooShort)
		}
		f2 := binary.LittleEndian.Uint16(data[offset : offset+2])
		appData.Feature2 = &f2
		offset += 2
	}

	// Parse optional name (remaining bytes if FlagHasName set)
	if appData.Flags&FlagHasName != 0 {
		if offset < len(data) {
			appData.Name = string(data[offset:])
		}
	}

	return appData, nil
}

// NodeTypeName returns a human-readable name for the node type.
func NodeTypeName(t uint8) string {
	switch t {
	case NodeTypeChat:
		return "chat"
	case NodeTypeRepeater:
		return "repeater"
	case NodeTypeRoom:
		return "room"
	case NodeTypeSensor:
		return "sensor"
	default:
		if t == 0 {
			return "unknown"
		}
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// HasLocation returns true if the appdata includes location information.
func (a *AdvertAppData) HasLocation() bool {
	return a.Lat != nil && a.Lon != nil
}

// GetNodeTypeName returns the human-readable node type name.
func (a *AdvertAppData) GetNodeTypeName() string {
	return NodeTypeName(a.NodeType)
}
