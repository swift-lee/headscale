package hscontrol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestWeComRegisterRedirect(t *testing.T) {
	app := createTestApp(t)
	provider := NewAuthProviderWeCom(app, "https://headscale.example.com", &types.WeComConfig{
		Enabled:    true,
		CorpID:     "ww123",
		AgentID:    "1000002",
		CorpSecret: "secret",
		Expiry:     180 * 24 * time.Hour,
	})
	provider.qrConnectURL = "https://login.example.com/wwopen/sso/qrConnect"

	registrationID, err := types.NewRegistrationID()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/register/"+registrationID.String(), nil)
	req = mux.SetURLVars(req, map[string]string{"registration_id": registrationID.String()})
	resp := httptest.NewRecorder()

	provider.RegisterHandler(resp, req)

	require.Equal(t, http.StatusFound, resp.Code)
	location, err := url.Parse(resp.Header().Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, "login.example.com", location.Host)
	assert.Equal(t, "ww123", location.Query().Get("appid"))
	assert.Equal(t, "1000002", location.Query().Get("agentid"))
	assert.Equal(t, "https://headscale.example.com/wecom/callback", location.Query().Get("redirect_uri"))

	state := location.Query().Get("state")
	require.NotEmpty(t, state)
	_, ok := provider.registrationCache.Get(state)
	assert.True(t, ok)

	cookies := resp.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, getCookieName("state", state), cookies[0].Name)
	assert.Equal(t, weComCallbackPath, cookies[0].Path)
}

func TestWeComCallbackRegistersNode(t *testing.T) {
	app := createTestApp(t)
	var tokenCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			tokenCalls.Add(1)
			assert.Equal(t, "ww123", r.URL.Query().Get("corpid"))
			assert.Equal(t, "secret", r.URL.Query().Get("corpsecret"))
			writeJSON(t, w, weComTokenResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				AccessToken:   "token",
				ExpiresIn:     7200,
			})
		case "/cgi-bin/user/getuserinfo":
			assert.Equal(t, "token", r.URL.Query().Get("access_token"))
			assert.Equal(t, "code-ok", r.URL.Query().Get("code"))
			writeJSON(t, w, weComUserInfoResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				UserID:        "Zhang.San",
			})
		case "/cgi-bin/user/get":
			assert.Equal(t, "token", r.URL.Query().Get("access_token"))
			assert.Equal(t, "Zhang.San", r.URL.Query().Get("userid"))
			writeJSON(t, w, weComUserDetailResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				UserID:        "Zhang.San",
				Name:          "Zhang San",
				Email:         "zhangsan@example.com",
				Avatar:        "https://example.com/avatar.png",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	provider := NewAuthProviderWeCom(app, "https://headscale.example.com", &types.WeComConfig{
		Enabled:        true,
		CorpID:         "ww123",
		AgentID:        "1000002",
		CorpSecret:     "secret",
		AllowedUserIDs: []string{"Zhang.San"},
		Expiry:         180 * 24 * time.Hour,
	})
	provider.apiBaseURL = api.URL

	registrationID, err := types.NewRegistrationID()
	require.NoError(t, err)
	state := "state-token"
	provider.registrationCache.Set(state, RegistrationInfo{RegistrationID: registrationID})
	app.state.SetRegistrationCacheEntry(registrationID, types.RegisterNode{
		Node: types.Node{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			DiscoKey:   key.NewDisco().Public(),
			Hostname:   "wecom-node",
			Hostinfo:   &tailcfg.Hostinfo{Hostname: "wecom-node"},
		},
		Registered: make(chan *types.Node, 1),
	})

	req := httptest.NewRequest(http.MethodGet, "/wecom/callback?code=code-ok&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: state})
	resp := httptest.NewRecorder()

	provider.CallbackHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, int32(1), tokenCalls.Load())

	user, err := app.state.GetUserByOIDCIdentifier("wecom/ww123/Zhang.San")
	require.NoError(t, err)
	assert.Equal(t, "zhang.san", user.Name)
	assert.Equal(t, "Zhang San", user.DisplayName)
	assert.Equal(t, "zhangsan@example.com", user.Email)
	assert.Equal(t, util.RegisterMethodWeCom, user.Provider)

	nodes := app.state.ListNodes()
	require.Equal(t, 1, nodes.Len())
	assert.Equal(t, util.RegisterMethodWeCom, nodes.At(0).RegisterMethod())
}

func TestWeComCallbackRejectsInvalidState(t *testing.T) {
	app := createTestApp(t)
	provider := NewAuthProviderWeCom(app, "https://headscale.example.com", &types.WeComConfig{
		Enabled:    true,
		CorpID:     "ww123",
		AgentID:    "1000002",
		CorpSecret: "secret",
		Expiry:     180 * 24 * time.Hour,
	})

	req := httptest.NewRequest(http.MethodGet, "/wecom/callback?code=code-ok&state=state-token", nil)
	req.AddCookie(&http.Cookie{Name: getCookieName("state", "state-token"), Value: "other-state"})
	resp := httptest.NewRecorder()

	provider.CallbackHandler(resp, req)

	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestWeComProfileFromCodeFailures(t *testing.T) {
	tests := []struct {
		name        string
		allowedIDs []string
		userInfo    weComUserInfoResponse
		wantStatus  int
	}{
		{
			name: "api-error",
			userInfo: weComUserInfoResponse{
				weComAPIError: weComAPIError{ErrCode: 40029, ErrMsg: "invalid code"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "external-user",
			userInfo: weComUserInfoResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				OpenID:        "openid",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:        "not-allowed",
			allowedIDs: []string{"lisi"},
			userInfo: weComUserInfoResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				UserID:        "zhangsan",
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := createTestApp(t)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/cgi-bin/gettoken":
					writeJSON(t, w, weComTokenResponse{
						weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
						AccessToken:   "token",
						ExpiresIn:     7200,
					})
				case "/cgi-bin/user/getuserinfo":
					writeJSON(t, w, tt.userInfo)
				default:
					http.NotFound(w, r)
				}
			}))
			defer api.Close()

			provider := NewAuthProviderWeCom(app, "https://headscale.example.com", &types.WeComConfig{
				Enabled:        true,
				CorpID:         "ww123",
				AgentID:        "1000002",
				CorpSecret:     "secret",
				AllowedUserIDs: tt.allowedIDs,
				Expiry:         180 * 24 * time.Hour,
			})
			provider.apiBaseURL = api.URL

			_, err := provider.profileFromCode(t.Context(), "code")
			require.Error(t, err)

			var httpErr HTTPError
			require.ErrorAs(t, err, &httpErr)
			assert.Equal(t, tt.wantStatus, httpErr.Code)
		})
	}
}

func TestWeComAccessTokenCache(t *testing.T) {
	app := createTestApp(t)
	var tokenCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			tokenCalls.Add(1)
			writeJSON(t, w, weComTokenResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				AccessToken:   "token",
				ExpiresIn:     7200,
			})
		case "/cgi-bin/user/getuserinfo":
			writeJSON(t, w, weComUserInfoResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				UserID:        "zhangsan",
			})
		case "/cgi-bin/user/get":
			writeJSON(t, w, weComUserDetailResponse{
				weComAPIError: weComAPIError{ErrCode: 0, ErrMsg: "ok"},
				UserID:        "zhangsan",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	provider := NewAuthProviderWeCom(app, "https://headscale.example.com", &types.WeComConfig{
		Enabled:    true,
		CorpID:     "ww123",
		AgentID:    "1000002",
		CorpSecret: "secret",
		Expiry:     180 * 24 * time.Hour,
	})
	provider.apiBaseURL = api.URL

	_, err := provider.profileFromCode(t.Context(), "code-one")
	require.NoError(t, err)
	_, err = provider.profileFromCode(t.Context(), "code-two")
	require.NoError(t, err)

	assert.Equal(t, int32(1), tokenCalls.Load())
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("failed to write JSON response: %v", err)
	}
}
