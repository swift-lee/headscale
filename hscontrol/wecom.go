package hscontrol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"zgo.at/zcache/v2"
)

const (
	weComQRCodeLoginURL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	weComAPIBaseURL     = "https://qyapi.weixin.qq.com"
	weComCallbackPath   = "/wecom/callback"
	weComTokenSkew      = 5 * time.Minute
)

var (
	errWeComAPI              = errors.New("wecom api error")
	errWeComAllowedUserIDs   = errors.New("authenticated wecom user is not allowed")
	errWeComEmptyUserID      = errors.New("wecom did not return a userid")
	errWeComExternalUser     = errors.New("authenticated wecom principal is not an enterprise member")
	invalidWeComUsernameChar = regexp.MustCompile(`[^a-z0-9._@-]+`)
)

type AuthProviderWeCom struct {
	h                 *Headscale
	serverURL         string
	cfg               *types.WeComConfig
	registrationCache *zcache.Cache[string, RegistrationInfo]

	httpClient    *http.Client
	qrConnectURL  string
	apiBaseURL    string
	now           func() time.Time
	accessTokenMu sync.Mutex
	accessToken   string
	tokenExpiry   time.Time
}

type weComAPIError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type weComTokenResponse struct {
	weComAPIError
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type weComUserInfoResponse struct {
	weComAPIError
	UserID string `json:"UserId"`
	OpenID string `json:"OpenId"`
}

type weComUserDetailResponse struct {
	weComAPIError
	UserID      string `json:"userid"`
	Name        string `json:"name"`
	Alias       string `json:"alias"`
	Email       string `json:"email"`
	Avatar      string `json:"avatar"`
	ThumbAvatar string `json:"thumb_avatar"`
}

type weComUserProfile struct {
	UserID        string
	Name          string
	Email         string
	Avatar        string
	ProviderID    string
	HeadscaleName string
}

func NewAuthProviderWeCom(
	h *Headscale,
	serverURL string,
	cfg *types.WeComConfig,
) *AuthProviderWeCom {
	return &AuthProviderWeCom{
		h:                 h,
		serverURL:         serverURL,
		cfg:               cfg,
		registrationCache: zcache.New[string, RegistrationInfo](registerCacheExpiration, registerCacheCleanup),
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		qrConnectURL:      weComQRCodeLoginURL,
		apiBaseURL:        weComAPIBaseURL,
		now:               time.Now,
	}
}

func (a *AuthProviderWeCom) AuthURL(registrationID types.RegistrationID) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		registrationID.String())
}

func (a *AuthProviderWeCom) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	registrationIDStr := vars["registration_id"]

	registrationID, err := types.RegistrationIDFromString(registrationIDStr)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "invalid registration id", err))
		return
	}

	state, err := setCSRFCookieForPath(writer, req, "state", weComCallbackPath)
	if err != nil {
		httpError(writer, err)
		return
	}

	a.registrationCache.Set(state, RegistrationInfo{RegistrationID: registrationID})

	authURL, err := a.authCodeURL(state)
	if err != nil {
		httpError(writer, err)
		return
	}

	log.Debug().Caller().Msgf("Redirecting to %s for WeCom authentication", authURL)
	http.Redirect(writer, req, authURL, http.StatusFound)
}

func (a *AuthProviderWeCom) authCodeURL(state string) (string, error) {
	authURL, err := url.Parse(a.qrConnectURL)
	if err != nil {
		return "", fmt.Errorf("parsing wecom qr connect URL: %w", err)
	}

	query := authURL.Query()
	query.Set("appid", a.cfg.CorpID)
	query.Set("agentid", a.cfg.AgentID)
	query.Set("redirect_uri", strings.TrimSuffix(a.serverURL, "/")+weComCallbackPath)
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

func (a *AuthProviderWeCom) CallbackHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := extractCodeAndStateParamFromRequest(req)
	if err != nil {
		httpError(writer, err)
		return
	}

	stateCookieName := getCookieName("state", state)
	cookieState, err := req.Cookie(stateCookieName)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "state not found", err))
		return
	}

	if state != cookieState.Value {
		httpError(writer, NewHTTPError(http.StatusForbidden, "state did not match", nil))
		return
	}

	profile, err := a.profileFromCode(req.Context(), code)
	if err != nil {
		httpError(writer, err)
		return
	}

	user, c, err := a.createOrUpdateUser(profile)
	if err != nil {
		log.Error().Err(err).Caller().Msg("could not create or update WeCom user")
		httpError(writer, NewHTTPError(http.StatusInternalServerError, "could not create or update user", err))
		return
	}

	a.h.Change(c)

	registrationID := a.getRegistrationIDFromState(state)
	if registrationID == nil {
		httpError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))
		return
	}

	verb := "Reauthenticated"
	newNode, err := a.handleRegistration(user, *registrationID, a.now().Add(a.cfg.Expiry))
	if err != nil {
		if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
			log.Debug().Caller().Str("registration_id", registrationID.String()).Msg("registration session expired before authorization completed")
			httpError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", err))

			return
		}
		httpError(writer, err)
		return
	}

	if newNode {
		verb = "Authenticated"
	}

	content := templates.OIDCCallback(user.Display(), verb).Render()
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write([]byte(content)); err != nil {
		util.LogErr(err, "Failed to write HTTP response")
	}
}

func (a *AuthProviderWeCom) getRegistrationIDFromState(state string) *types.RegistrationID {
	regInfo, ok := a.registrationCache.Get(state)
	if !ok {
		return nil
	}

	return &regInfo.RegistrationID
}

func (a *AuthProviderWeCom) profileFromCode(ctx context.Context, code string) (*weComUserProfile, error) {
	token, err := a.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	userInfoURL := a.apiURL("/cgi-bin/user/getuserinfo", map[string]string{
		"access_token": token,
		"code":         code,
	})

	var userInfo weComUserInfoResponse
	if err := a.getJSON(ctx, userInfoURL, &userInfo); err != nil {
		return nil, err
	}
	if userInfo.ErrCode != 0 {
		return nil, NewHTTPError(http.StatusForbidden, "invalid wecom code", userInfo.apiError())
	}
	if userInfo.UserID == "" {
		if userInfo.OpenID != "" {
			return nil, NewHTTPError(http.StatusUnauthorized, "not an enterprise wecom user", errWeComExternalUser)
		}

		return nil, NewHTTPError(http.StatusUnauthorized, "empty wecom userid", errWeComEmptyUserID)
	}

	if len(a.cfg.AllowedUserIDs) > 0 && !slices.Contains(a.cfg.AllowedUserIDs, userInfo.UserID) {
		return nil, NewHTTPError(http.StatusUnauthorized, "unauthorised wecom user", errWeComAllowedUserIDs)
	}

	profile := &weComUserProfile{
		UserID:        userInfo.UserID,
		ProviderID:    a.providerIdentifier(userInfo.UserID),
		HeadscaleName: weComHeadscaleUsername(userInfo.UserID),
	}

	detail, err := a.userDetail(ctx, token, userInfo.UserID)
	if err != nil {
		util.LogErr(err, "could not get WeCom user detail; only using userid")
		return profile, nil
	}

	profile.Name = detail.Name
	if profile.Name == "" {
		profile.Name = detail.Alias
	}
	profile.Email = detail.Email
	profile.Avatar = detail.Avatar
	if profile.Avatar == "" {
		profile.Avatar = detail.ThumbAvatar
	}
	if profile.HeadscaleName == "" {
		profile.HeadscaleName = weComHeadscaleUsername(detail.UserID)
	}

	return profile, nil
}

func (a *AuthProviderWeCom) userDetail(
	ctx context.Context,
	token string,
	userID string,
) (*weComUserDetailResponse, error) {
	userURL := a.apiURL("/cgi-bin/user/get", map[string]string{
		"access_token": token,
		"userid":       userID,
	})

	var detail weComUserDetailResponse
	if err := a.getJSON(ctx, userURL, &detail); err != nil {
		return nil, err
	}
	if detail.ErrCode != 0 {
		return nil, detail.apiError()
	}

	return &detail, nil
}

func (a *AuthProviderWeCom) getAccessToken(ctx context.Context) (string, error) {
	a.accessTokenMu.Lock()
	defer a.accessTokenMu.Unlock()

	if a.accessToken != "" && a.now().Before(a.tokenExpiry) {
		return a.accessToken, nil
	}

	tokenURL := a.apiURL("/cgi-bin/gettoken", map[string]string{
		"corpid":     a.cfg.CorpID,
		"corpsecret": a.cfg.CorpSecret,
	})

	var tokenResp weComTokenResponse
	if err := a.getJSON(ctx, tokenURL, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.ErrCode != 0 {
		return "", NewHTTPError(http.StatusBadGateway, "could not get wecom access token", tokenResp.apiError())
	}
	if tokenResp.AccessToken == "" {
		return "", NewHTTPError(http.StatusBadGateway, "empty wecom access token", errWeComAPI)
	}

	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	skew := weComTokenSkew
	if expiresIn <= skew {
		skew = expiresIn / 10
	}
	a.accessToken = tokenResp.AccessToken
	a.tokenExpiry = a.now().Add(expiresIn - skew)

	return a.accessToken, nil
}

func (a *AuthProviderWeCom) apiURL(path string, params map[string]string) string {
	apiURL, _ := url.Parse(strings.TrimSuffix(a.apiBaseURL, "/") + path)
	query := apiURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	apiURL.RawQuery = query.Encode()

	return apiURL.String()
}

func (a *AuthProviderWeCom) getJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating wecom request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling wecom api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return NewHTTPError(http.StatusBadGateway, "wecom api returned non-success status", fmt.Errorf("status code: %d", resp.StatusCode))
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decoding wecom api response: %w", err)
	}

	return nil
}

func (e weComAPIError) apiError() error {
	return fmt.Errorf("%w: errcode=%d errmsg=%q", errWeComAPI, e.ErrCode, e.ErrMsg)
}

func (a *AuthProviderWeCom) providerIdentifier(userID string) string {
	return fmt.Sprintf("wecom/%s/%s", a.cfg.CorpID, userID)
}

func (a *AuthProviderWeCom) createOrUpdateUser(
	profile *weComUserProfile,
) (*types.User, change.ChangeSet, error) {
	var user *types.User
	var err error
	var newUser bool

	user, err = a.h.state.GetUserByOIDCIdentifier(profile.ProviderID)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, change.EmptySet, fmt.Errorf("creating or updating wecom user: %w", err)
	}

	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.Name = profile.HeadscaleName
	user.DisplayName = profile.Name
	user.ProfilePicURL = profile.Avatar
	user.ProviderIdentifier = sql.NullString{String: profile.ProviderID, Valid: true}
	user.Provider = util.RegisterMethodWeCom
	if _, err := mail.ParseAddress(profile.Email); err == nil {
		user.Email = profile.Email
	}

	if newUser {
		user, c, err := a.h.state.CreateUser(*user)
		if err != nil {
			return nil, change.EmptySet, fmt.Errorf("creating wecom user: %w", err)
		}

		return user, c, nil
	}

	_, c, err := a.h.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
		*u = *user
		return nil
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("updating wecom user: %w", err)
	}

	return user, c, nil
}

func (a *AuthProviderWeCom) handleRegistration(
	user *types.User,
	registrationID types.RegistrationID,
	expiry time.Time,
) (bool, error) {
	node, nodeChange, err := a.h.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodWeCom,
	)
	if err != nil {
		return false, fmt.Errorf("could not register node: %w", err)
	}

	_ = a.h.state.AutoApproveRoutes(node)
	_, policyChange, err := a.h.state.SaveNode(node)
	if err != nil {
		return false, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	if !policyChange.Empty() {
		a.h.Change(policyChange)
	} else {
		a.h.Change(nodeChange)
	}

	return !nodeChange.Empty(), nil
}

func weComHeadscaleUsername(userID string) string {
	username := strings.ToLower(strings.TrimSpace(userID))
	username = invalidWeComUsernameChar.ReplaceAllString(username, "-")
	username = strings.Trim(username, "-._@")
	if err := util.ValidateUsername(username); err == nil {
		return username
	}

	hash := sha256.Sum256([]byte(userID))

	return "wecom-" + hex.EncodeToString(hash[:])[:12]
}
