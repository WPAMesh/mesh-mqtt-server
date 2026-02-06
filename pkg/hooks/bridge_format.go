package hooks

import (
	"strings"
)

// FormatMeshtasticToMeshCore formats a message for bridging from Meshtastic to MeshCore.
// MeshCore expects group messages in "SenderName: message" format.
func FormatMeshtasticToMeshCore(senderName, message, prefix string) string {
	var sb strings.Builder

	if prefix != "" {
		sb.WriteString(prefix)
	}

	if senderName != "" {
		sb.WriteString(senderName)
		sb.WriteString(": ")
	}

	sb.WriteString(message)
	return sb.String()
}

// FormatMeshCoreToMeshtastic formats a message for bridging from MeshCore to Meshtastic.
// If parseSender is true, attempts to extract sender from "Name: message" format.
func FormatMeshCoreToMeshtastic(message, prefix string, parseSender bool) (formattedMsg string, extractedSender string) {
	var sb strings.Builder

	if prefix != "" {
		sb.WriteString(prefix)
	}

	if parseSender {
		sender, msg, found := ParseSenderFromMessage(message)
		if found {
			extractedSender = sender
			sb.WriteString(sender)
			sb.WriteString(": ")
			sb.WriteString(msg)
			return sb.String(), extractedSender
		}
	}

	sb.WriteString(message)
	return sb.String(), ""
}

// ParseSenderFromMessage attempts to extract sender name from "Name: message" format.
// Returns the sender name, remaining message, and whether parsing succeeded.
func ParseSenderFromMessage(message string) (sender, remaining string, found bool) {
	// Look for the first ": " separator
	idx := strings.Index(message, ": ")
	if idx == -1 {
		return "", message, false
	}

	// Sender name should be reasonable (1-32 chars, no newlines)
	potentialSender := message[:idx]
	if len(potentialSender) < 1 || len(potentialSender) > 32 {
		return "", message, false
	}

	// Sender name shouldn't contain newlines or other control characters
	for _, r := range potentialSender {
		if r < 32 || r == 127 {
			return "", message, false
		}
	}

	return potentialSender, message[idx+2:], true
}

// HasBridgePrefix checks if a message already has one of the bridge prefixes.
// Used for loop prevention.
func HasBridgePrefix(message, meshtasticPrefix, meshCorePrefix string) bool {
	if meshtasticPrefix != "" && strings.HasPrefix(message, meshtasticPrefix) {
		return true
	}
	if meshCorePrefix != "" && strings.HasPrefix(message, meshCorePrefix) {
		return true
	}
	return false
}

// TruncateMessage truncates a message to fit within maxLen bytes.
// Tries to break at word boundaries if possible.
func TruncateMessage(message string, maxLen int) string {
	if len(message) <= maxLen {
		return message
	}

	// Try to find a space to break at
	truncated := message[:maxLen]
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > maxLen/2 {
		return truncated[:lastSpace]
	}

	return truncated
}
