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
	"log"
	"net/http"
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

func (wr *WebRouter) discordLoginHandler(w http.ResponseWriter, r *http.Request) {
	oauthStateString := generateStateOauthCookie(w)
	url := wr.config.OAuth.Discord.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (wr *WebRouter) userLogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := wr.sessionStore.Get(r, sessionName)
	if err != nil {
		fmt.Fprint(w, err.Error())
	}
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (wr *WebRouter) discordCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	session, err := wr.sessionStore.Get(r, sessionName)
	if err != nil {
		fmt.Fprint(w, err.Error())
	}
	data, err := wr.getUserDataFromDiscord(code)
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	session.Values["user_id"] = data.ID
	session.Save(r, w)

	log.Printf("User authenticated: %v", data)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (wr *WebRouter) getUserDataFromDiscord(code string) (*models.User, error) {
	// Use code to get token and get user info from Google.
	token, err := wr.config.OAuth.Discord.Exchange(context.Background(), code)
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

	isValid, err := wr.validateDiscordUser(&gUser, token)
	if err != nil {
		return nil, fmt.Errorf("failed validating discord membership: %s", err.Error())
	}

	if !isValid {
		return nil, errors.New("discord user is not a member of this guild")
	}

	return wr.saveToken(gUser, token)
}

func (wr *WebRouter) validateDiscordUser(gUser *models.DiscordUser, token *oauth2.Token) (bool, error) {

	return wr.getDiscordGuildStatus(token)
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
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, err
}

func (wr *WebRouter) getDiscordGuildStatus(token *oauth2.Token) (bool, error) {

	guildID := "1330739329538195588" //wpamesh
	//guildID := "1330739329538195695" //unknown
	guildMemberEndpoint := fmt.Sprintf("%s/users/@me/guilds/%s/member", discordAPIBase, guildID)

	// Create a new request using http
	body, err := wr.getAuthEndpoint(guildMemberEndpoint, token)
	if err != nil {
		return false, err
	}
	dm := models.DiscordGuildMember{}

	err = json.Unmarshal(body, &dm)
	if err != nil {
		return false, err
	}
	if dm.User == nil {
		return false, fmt.Errorf("user is not a member of guild %s", guildID)
	}
	return !*dm.Pending, nil
}

func (wr *WebRouter) saveToken(gUser models.DiscordUser, token *oauth2.Token) (*models.User, error) {
	discordID, err := strconv.ParseInt(gUser.ID, 10, 64)
	if err != nil {
		return nil, err
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
		userId, err := wr.storage.Users.GetByDiscordID(discordID)
		//userId, err := storage.Users.SaveUser(&models.User{
		//	DisplayName: gUser.Name,
		//})
		if err != nil {
			return nil, err
		}
		dbToken = models.OAuthToken{
			UserID:       userId.ID,
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
	return wr.storage.Users.GetByID(dbToken.UserID)
}
