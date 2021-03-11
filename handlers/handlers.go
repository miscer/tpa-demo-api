package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"tpa-api/providers/facebook"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
)

type Handlers struct {
	Config Config
}

type AuthURLInput struct {
	RedirectURL string `json:"redirect_url"`
}

type AuthURLOutput struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

func (h *Handlers) GetAuthURL(c *gin.Context) {
	var input AuthURLInput
	err := c.ShouldBindJSON(&input)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid input: %v", err)
		return
	}

	provider := h.createFacebookProvider(input.RedirectURL)

	state := generateStateToken()
	session, err := provider.BeginAuth(state)
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	url, err := session.GetAuthURL()
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	c.JSON(http.StatusOK, AuthURLOutput{
		AuthorizationURL: url,
		State:            state,
	})
}

type Params map[string]string

func (p Params) Get(key string) string {
	if value, ok := p[key]; ok {
		return value
	}
	return ""
}

type CompleteAuthInput struct {
	State       string `json:"state"`
	RedirectURL string `json:"redirect_url"`
	Params      Params `json:"params"`
}

type CompleteAuthSuccessOutput struct {
	Email string `json:"email"`
}

type CompleteAuthErrorOutput struct {
	Error    string `json:"error"`
	RetryURL string `json:"retry_url"`
}

func (h *Handlers) CompleteAuth(c *gin.Context) {
	var input CompleteAuthInput
	err := c.ShouldBindJSON(&input)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid input: %v", err)
		return
	}

	if input.State != input.Params.Get("state") {
		c.JSON(http.StatusOK, CompleteAuthErrorOutput{
			Error: "state_token_mismatch",
		})
		return
	}

	provider := h.createFacebookProvider(input.RedirectURL)

	if input.Params.Get("error") != "" {
		c.JSON(http.StatusOK, CompleteAuthErrorOutput{
			Error: input.Params.Get("error"),
		})
		return
	}

	session, err := provider.BeginAuth(input.State)
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	_, err = session.Authorize(provider, input.Params)
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	user, err := provider.FetchUser(session)
	if err != nil {
		c.String(http.StatusInternalServerError, "Fetching user failed: %v", err)
		return
	}

	if user.Email == "" {
		if p, ok := provider.(*facebook.Provider); ok {
			p.SetOptions(facebook.RerequestOption)
		}

		session, err := provider.BeginAuth(input.State)
		if err != nil {
			c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
			return
		}

		url, err := session.GetAuthURL()
		if err != nil {
			c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
			return
		}

		c.JSON(http.StatusOK, CompleteAuthErrorOutput{
			Error:    "email_missing",
			RetryURL: url,
		})
		return
	}

	c.JSON(http.StatusOK, CompleteAuthSuccessOutput{
		Email: user.Email,
	})
}

func (h *Handlers) createFacebookProvider(redirectURL string) goth.Provider {
	return facebook.New(h.Config.FacebookClientID, h.Config.FacebookClientSecret, redirectURL)
}

func generateStateToken() string {
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}
