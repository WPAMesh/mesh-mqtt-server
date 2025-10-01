package hooks

import (
	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
)

func (h *MeshtasticHook) validateUser(user, pass string) *models.User {
	u, err := h.config.Storage.Users.GetByUserName(user)
	if err != nil {
		h.Log.Error("unable to query mqtt user", "hook", h.ID(), "user", user, "error", err)
		return nil
	}

	if u == nil {
		return nil
	}
	if auth.HashPasswordWithSalt(pass, u.Salt) == u.PasswordHash {
		return u
	}
	return nil
}
