package discord

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
)

const (
	discordAPIBase      = "https://discord.com/api/v10"
	defaultSyncInterval = 15 * time.Minute
)

// RoleSync periodically checks Discord guild membership and updates admin
// status for all registered users that have a Discord ID.
type RoleSync struct {
	discord  config.DiscordSettings
	storage  store.Stores
	client   *http.Client
	stopChan chan struct{}
}

// NewRoleSync creates a new RoleSync instance. Returns nil if the necessary
// configuration (BotToken and AdminRoleID) is not present.
func NewRoleSync(discord config.DiscordSettings, storage store.Stores) *RoleSync {
	if discord.BotToken == "" || discord.AdminRoleID == "" {
		slog.Info("discord role sync disabled: botToken and adminRoleId both required")
		return nil
	}
	if discord.GuildID == "" {
		slog.Warn("discord role sync disabled: guildId is required")
		return nil
	}
	return &RoleSync{
		discord:  discord,
		storage:  storage,
		client:   &http.Client{Timeout: 10 * time.Second},
		stopChan: make(chan struct{}),
	}
}

// Start begins the background sync loop. It runs an initial sync immediately,
// then repeats at the configured interval. This method blocks and should be
// called in a goroutine.
func (rs *RoleSync) Start() {
	slog.Info("starting discord admin role sync",
		"interval", defaultSyncInterval,
		"guild_id", rs.discord.GuildID,
		"admin_role_id", rs.discord.AdminRoleID)

	rs.syncAll()

	ticker := time.NewTicker(defaultSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rs.stopChan:
			slog.Info("stopping discord admin role sync")
			return
		case <-ticker.C:
			rs.syncAll()
		}
	}
}

// Stop signals the background loop to exit.
func (rs *RoleSync) Stop() {
	close(rs.stopChan)
}

// syncAll fetches all users from the DB and checks each one's Discord roles.
func (rs *RoleSync) syncAll() {
	users, err := rs.storage.Users.GetAll()
	if err != nil {
		slog.Error("discord role sync: failed to fetch users", "error", err)
		return
	}

	updated := 0
	checked := 0
	for _, user := range users {
		if user.DiscordID == nil {
			continue
		}
		if user.IsSuperuser {
			continue
		}

		checked++
		discordID := strconv.FormatInt(*user.DiscordID, 10)

		hasRole, err := rs.checkMemberRole(discordID)
		if err != nil {
			slog.Warn("discord role sync: failed to check user",
				"user_id", user.ID,
				"discord_id", discordID,
				"error", err)
			continue
		}

		if hasRole != user.IsAdmin {
			slog.Info("discord role sync: updating admin status",
				"user_id", user.ID,
				"username", user.UserName,
				"old_admin", user.IsAdmin,
				"new_admin", hasRole)
			if err := rs.storage.Users.SetAdminStatus(user.ID, hasRole); err != nil {
				slog.Error("discord role sync: failed to update admin status",
					"user_id", user.ID,
					"error", err)
				continue
			}
			updated++
		}

		// Basic rate limiting: Discord allows ~10 requests per 10 seconds
		// for this endpoint. Sleeping 1 second keeps us well under the limit.
		time.Sleep(1 * time.Second)
	}

	if checked > 0 {
		slog.Info("discord role sync complete",
			"users_checked", checked,
			"users_updated", updated)
	}
}

// checkMemberRole fetches a single guild member by Discord user ID and checks
// if they have the configured admin role.
func (rs *RoleSync) checkMemberRole(discordUserID string) (bool, error) {
	url := fmt.Sprintf("%s/guilds/%s/members/%s",
		discordAPIBase, rs.discord.GuildID, discordUserID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+rs.discord.BotToken)

	resp, err := rs.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("discord API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// User is not in the guild — remove admin
		return false, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		var rateLimitResp struct {
			RetryAfter float64 `json:"retry_after"`
		}
		if err := json.Unmarshal(body, &rateLimitResp); err == nil && rateLimitResp.RetryAfter > 0 {
			sleepDuration := time.Duration(rateLimitResp.RetryAfter*1000) * time.Millisecond
			slog.Warn("discord role sync: rate limited, sleeping",
				"retry_after_seconds", rateLimitResp.RetryAfter)
			time.Sleep(sleepDuration)
		}
		return false, fmt.Errorf("rate limited by Discord API")
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("discord API returned status %d: %s",
			resp.StatusCode, string(body))
	}

	var member models.DiscordGuildMember
	if err := json.Unmarshal(body, &member); err != nil {
		return false, fmt.Errorf("unmarshalling guild member: %w", err)
	}

	for _, role := range member.Roles {
		if role == rs.discord.AdminRoleID {
			return true, nil
		}
	}
	return false, nil
}
