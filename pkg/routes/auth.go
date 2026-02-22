package routes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/sessions"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"golang.org/x/oauth2"
)

var (
	discordAPIBase string = "https://discord.com/api/v10"
)

// getUser returns a user from session s
// on error returns an empty user
func (wr *WebRouter) getUser(s *sessions.Session) (*models.User, error) {
	val := s.Values["user_id"]
	user_id, ok := val.(int)
	if !ok {
		return nil, errors.New("not logged in")
	}
	return wr.storage.Users.GetByID(user_id)
}

func generateStateOauthCookie(http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	return state
}

func (wr *WebRouter) getDiscordRedirectURI(r *http.Request) string {
	redir, err := url.Parse(wr.config.OAuth.Discord.RedirectURL)
	if err == nil {
		redir.Host = r.Host
	}
	return redir.String()
}

func (wr *WebRouter) discordLoginHandler(w http.ResponseWriter, r *http.Request) {
	oauthStateString := generateStateOauthCookie(w)
	redir := wr.getDiscordRedirectURI(r)
	redirURI := oauth2.SetAuthURLParam("redirect_uri", redir)

	url := wr.config.OAuth.Discord.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline, redirURI /*, oauth2.ApprovalForce*/)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (wr *WebRouter) userLogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := wr.sessionStore.Get(r, sessionName)
	if err != nil {
		fmt.Fprint(w, err.Error())
	}
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		fmt.Fprint(w, err.Error())
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (wr *WebRouter) discordCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	session, err := wr.sessionStore.Get(r, sessionName)
	if err != nil {
		fmt.Fprint(w, err.Error())
		slog.Error("error loading user session", "error", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	data, err := wr.getUserDataFromDiscord(code, r)
	if err != nil {
		slog.Error("error fetching user data from token", "error", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	session.Values["user_id"] = data.ID
	err = session.Save(r, w)

	if err != nil {
		fmt.Fprint(w, err.Error())
		slog.Error("saving session", "error", err)
	}

	slog.Info("user authenticated", "user", data.UserName)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (wr *WebRouter) getUserDataFromDiscord(code string, r *http.Request) (*models.User, error) {
	// Use code to get token and get user info from Google.
	redir := wr.getDiscordRedirectURI(r)
	redirURI := oauth2.SetAuthURLParam("redirect_uri", redir)
	token, err := wr.config.OAuth.Discord.Exchange(context.Background(), code, redirURI)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed with error: %s", err.Error())
	}

	if !token.Valid() {
		return nil, fmt.Errorf("retreived invalid token")
	}

	response, err := wr.getAuthEndpoint(discordAPIBase+"/users/@me", token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	var gUser models.DiscordUser
	err = json.Unmarshal(response, &gUser)
	if err != nil {
		return nil, err
	}

	isValid, isAdmin, err := wr.validateDiscordUser(&gUser, token)
	if err != nil {
		return nil, fmt.Errorf("failed validating discord membership: %s", err.Error())
	}

	if !isValid {
		return nil, errors.New("discord user is not a member of this guild")
	}

	return wr.saveToken(gUser, token, isAdmin)
}

func (wr *WebRouter) validateDiscordUser(gUser *models.DiscordUser, token *oauth2.Token) (isValid bool, isAdmin bool, err error) {
	dm, err := wr.getDiscordGuildMember(token)
	if err != nil {
		return false, false, err
	}
	if dm.Pending != nil && *dm.Pending {
		return false, false, nil
	}

	// Check if user has the admin role
	adminRoleID := wr.config.Discord.AdminRoleID
	if adminRoleID != "" {
		for _, role := range dm.Roles {
			if role == adminRoleID {
				isAdmin = true
				break
			}
		}
	}

	return true, isAdmin, nil
}

func (wr *WebRouter) getAuthEndpoint(url string, token *oauth2.Token) ([]byte, error) {
	// Create a new request using http
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %s", err.Error())
	}

	token.SetAuthHeader(req)

	// Send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("error calling authenticated endpoint", "error", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, err
}

func (wr *WebRouter) getDiscordGuildMember(token *oauth2.Token) (*models.DiscordGuildMember, error) {
	guildID := wr.config.Discord.GuildID
	guildMemberEndpoint := fmt.Sprintf("%s/users/@me/guilds/%s/member", discordAPIBase, guildID)

	body, err := wr.getAuthEndpoint(guildMemberEndpoint, token)
	if err != nil {
		return nil, err
	}
	dm := models.DiscordGuildMember{}

	err = json.Unmarshal(body, &dm)
	if err != nil {
		return nil, err
	}
	if dm.User == nil {
		return nil, fmt.Errorf("user is not a member of guild %s", guildID)
	}
	return &dm, nil
}

func createMqttUsername(discordUser string) string {

	s := []byte(discordUser)
	j := 0
	for _, b := range s {
		if ('a' <= b && b <= 'z') ||
			('A' <= b && b <= 'Z') ||
			('0' <= b && b <= '9') ||
			b == '-' || b == '_' || b == '.' {
			s[j] = b
			j++
		}
	}
	return string(s[:j])
}

func (wr *WebRouter) saveToken(gUser models.DiscordUser, token *oauth2.Token, isAdmin bool) (*models.User, error) {
	discordID, err := strconv.ParseInt(gUser.ID, 10, 64)
	if err != nil {
		return nil, err
	}
	if gUser.Username == "" {
		return nil, errors.New("discord user does not have a username")
	}
	dbToken, err := wr.storage.OAuthTokens.GetTokenForDiscordID(discordID)
	switch err {
	case nil:
		dbToken.TokenType = &token.TokenType
		dbToken.AccessToken = &token.AccessToken
		if token.RefreshToken != "" {
			dbToken.RefreshToken = &token.RefreshToken
		}
		dbToken.Expiration = &token.Expiry
	case sql.ErrNoRows:
		// TODO: Create a new user entry and set their MQTT details
		user, err := wr.storage.Users.GetByDiscordID(discordID)
		if user == nil {
			user = &models.User{
				DisplayName: &gUser.Username,
				DiscordID:   &discordID,
				UserName:    createMqttUsername(gUser.Username),
				// Force empty to prevent login until user sets it
				PasswordHash: "",
				Salt:         "",
			}
			err = wr.storage.Users.AddUser(user)
			if err != nil {
				return nil, err
			}
			user, err = wr.storage.Users.GetByDiscordID(discordID)
		}
		if err != nil {
			return nil, err
		}
		dbToken = models.OAuthToken{
			UserID:       user.ID,
			TokenType:    &token.TokenType,
			AccessToken:  &token.AccessToken,
			RefreshToken: &token.RefreshToken,
			Expiration:   &token.Expiry,
		}
	default:
		return nil, err
	}
	err = wr.storage.OAuthTokens.SaveToken(dbToken)
	if err != nil {
		return nil, err
	}

	// Update admin status based on Discord role
	if err := wr.storage.Users.SetAdminStatus(dbToken.UserID, isAdmin); err != nil {
		slog.Error("error updating admin status", "error", err, "user_id", dbToken.UserID)
	}

	return wr.storage.Users.GetByID(dbToken.UserID)
}
