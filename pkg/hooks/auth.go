package hooks

import (
	"crypto/sha256"
	"encoding/hex"
)

type hashPair struct {
	Hash string
	Salt string
}

func hashPasswordWithSalt(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (h *MeshtasticHook) validateUser(user, pass string) bool {
	u, err := h.config.Storage.MqttUsers.GetByUserName(user)
	if err != nil {
		h.Log.Error("unable to query mqtt user", "hook", h.ID(), "user", user, "error", err)
		return false
	}

	if u == nil {
		return false
	}
	calcHash := hashPasswordWithSalt(pass, u.Salt)
	return u.PasswordHash == calcHash
}
