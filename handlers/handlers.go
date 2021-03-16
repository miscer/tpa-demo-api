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
	RedirectURL string `json:"redirect_url"` // Frontend URL where the third party will redirect to
}

type AuthURLOutput struct {
	AuthorizationURL string `json:"authorization_url"` // Third party URL where the user can log in
	State            string `json:"state"`             // Frontend has to save the state somewhere to do a CSRF check later
}

func (h *Handlers) GetAuthURL(c *gin.Context) {
	var input AuthURLInput
	err := c.ShouldBindJSON(&input)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid input: %v", err)
		return
	}

	// Only Facebook is supported for the demo.
	provider := h.createFacebookProvider(input.RedirectURL)

	// Random nonce is generated for each authorization request.
	state := generateStateToken()

	// The session is created only to get the authorization URL in the next step, it is not saved anywhere. It does not
	// contain anything useful at this point anyway.
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
	State       string `json:"state"`        // State returned from the first request, stored in the browser local storage
	RedirectURL string `json:"redirect_url"` // Same URL that was supplied to the first request
	Params      Params `json:"params"`       // Query parameters from the third party, usually contains the code and state
}

type CompleteAuthSuccessOutput struct {
	Email string `json:"email"` // Email address retrieved from the third party
}

type CompleteAuthErrorOutput struct {
	Error    string `json:"error"`     // Error code that frontend uses to show a suitable error message
	RetryURL string `json:"retry_url"` // If the error can be fixed, frontend can redirect the user to this URL
}

func (h *Handlers) CompleteAuth(c *gin.Context) {
	var input CompleteAuthInput
	err := c.ShouldBindJSON(&input)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid input: %v", err)
		return
	}

	// State returned from the first request (which is stored in browser local storage) has to be the same as the state
	// returned from the third party to prevent CSRF attacks.
	if input.State != input.Params.Get("state") {
		c.JSON(http.StatusOK, CompleteAuthErrorOutput{
			Error: "state_token_mismatch",
		})
		return
	}

	// The redirect URL has to be the same to make sure the provider has the same configuration.
	provider := h.createFacebookProvider(input.RedirectURL)

	// Forward any errors from the third party to frontend. In a proper implementation this should be more clever.
	if input.Params.Get("error") != "" {
		c.JSON(http.StatusOK, CompleteAuthErrorOutput{
			Error: input.Params.Get("error"),
		})
		return
	}

	// Recreate the session from the first request
	session, err := provider.BeginAuth(input.State)
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	// Get the access token from the query params returned from the third party. For OAuth only the `code` parameter
	// is used to get the access token, in combination with the redirect URL and client ID and secret.
	_, err = session.Authorize(provider, input.Params)
	if err != nil {
		c.String(http.StatusInternalServerError, "Authorization failed: %v", err)
		return
	}

	// Get user info, authenticated by the access token
	user, err := provider.FetchUser(session)
	if err != nil {
		c.String(http.StatusInternalServerError, "Fetching user failed: %v", err)
		return
	}

	// For demo purposes only. Email can be missing for multiple reasons, here we assume that the user disabled the
	// email permission on Facebook.
	if user.Email == "" {
		// We can ask the user for the permission by adding `?auth_type=rerequest` to the Facebook authorization URL.
		// Instead of manipulating the URL directly, we can use a custom provider and tell the OAuth library to add it.
		if p, ok := provider.(*facebook.Provider); ok {
			p.SetOptions(facebook.RerequestOption)
		}

		// Create a new session to make sure a new authorization URL is created, with the `auth_type` parameter.
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

		// User can fix the error by following the new authorization URL.
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
