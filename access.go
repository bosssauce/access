package access

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/nilslice/jwt"

	"github.com/ponzu-cms/ponzu/system/admin/user"
	"github.com/ponzu-cms/ponzu/system/db"
)

const (
	apiAccessStore  = "__apiAccess"
	apiAccessCookie = "_apiAccessToken"
)

// APIAccess is the data for an API access grant
type APIAccess struct {
	Email string `json:"email"`
	Hash  string `json:"hash"`
	Salt  string `json:"salt"`
	Token string `json:"token"`
}

// Config contains settings for token creation and validation
type Config struct {
	ExpireAfter    time.Duration
	ResponseWriter http.ResponseWriter
	TokenStore     reqHeaderOrHTTPCookie
	CustomClaims   map[string]interface{}
	SecureCookie   bool
}

type reqHeaderOrHTTPCookie interface{}

func init() {
	db.AddBucket(apiAccessStore)
}

// Grant creates a new APIAccess and saves it to the __apiAccess bucket in the database
// and if an existing APIAccess grant is encountered in the database, Grant attempts
// to update the grant but will fail if unauthorized
func Grant(email, password string, cfg *Config) (*APIAccess, error) {
	if email == "" {
		return nil, fmt.Errorf("%s", "email must not be empty")
	}

	if password == "" {
		return nil, fmt.Errorf("%s", "password must not be empty")
	}

	u, err := user.New(email, password)
	if err != nil {
		return nil, err
	}

	apiAccess := &APIAccess{
		Email: u.Email,
		Hash:  u.Hash,
		Salt:  u.Salt,
	}

	err = apiAccess.setToken(cfg)
	if err != nil {
		return nil, err
	}

	err = db.Store().Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiAccessStore))
		if b == nil {
			return fmt.Errorf("failed to get bucket %s", apiAccessStore)
		}

		if b.Get([]byte(u.Email)) != nil {
			err := updateGrant(email, password, cfg)
			if err != nil {
				return fmt.Errorf("failed to update APIAccess grant for %s, %v", u.Email, err)
			}
		}

		j, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("failed to marshal APIAccess to json, %v", err)
		}

		return b.Put([]byte(u.Email), j)
	})

	if err != nil {
		return nil, err
	}

	return apiAccess, nil
}

// IsGranted checks if the user request is authenticated by the token held within
// the provided tokenStore (should be a http.Cookie or http.Header)
func IsGranted(req *http.Request, tokenStore reqHeaderOrHTTPCookie) bool {
	token, err := getToken(req, tokenStore)
	if err != nil {
		log.Println("failed to get token to check API access grant")
		return false
	}

	return jwt.Passes(token)
}

// IsOwner validates the access token and checks the claims within the
// authenticated request's JWT for the email associated with the grant.
func IsOwner(req *http.Request, tokenStore reqHeaderOrHTTPCookie, email string) bool {
	token, err := getToken(req, tokenStore)
	if err != nil {
		log.Println("failed to get token to check API access owner")
		return false
	}

	if !jwt.Passes(token) {
		return false
	}

	claims := jwt.GetClaims(token)
	if claims["access"].(string) != email {
		return false
	}

	return true
}

func updateGrant(email, password string, cfg *Config) error {
	var apiAccess *APIAccess
	err := db.Store().View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiAccessStore))
		if b == nil {
			return fmt.Errorf("failed to get %s bucket to update grant", apiAccessStore)
		}

		j := b.Get([]byte(email))
		return json.Unmarshal(j, apiAccess)
	})
	if err != nil {
		return fmt.Errorf("failed to get access grant to update grant, %v", err)
	}

	usr := &user.User{
		Email: apiAccess.Email,
		Hash:  apiAccess.Hash,
		Salt:  apiAccess.Salt,
	}

	if !user.IsUser(usr, password) {
		return fmt.Errorf(
			"unauthorized attempt to update grant for %s", apiAccess.Email,
		)
	}

	return nil
}

func getToken(req *http.Request, tokenStore reqHeaderOrHTTPCookie) (string, error) {
	switch tokenStore.(type) {
	case http.Cookie:
		cookie, err := req.Cookie(apiAccessCookie)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil

	case http.Header:
		bearer := req.Header.Get("Authorization")
		return strings.TrimPrefix(bearer, "Bearer "), nil

	default:
		return "", fmt.Errorf("%s", "unrecognized token store")
	}
}

func (a *APIAccess) setToken(cfg *Config) error {
	exp := time.Now().Add(cfg.ExpireAfter)
	claims := map[string]interface{}{
		"exp":    exp.Unix(),
		"access": a.Email,
	}

	for k, v := range cfg.CustomClaims {
		if _, ok := claims[k]; ok {
			return fmt.Errorf(
				"custom Config claim [%s] collides with internal claim [%s], %s",
				k, k, "please rename custom claim",
			)
		}

		claims[k] = v
	}

	token, err := jwt.New(claims)
	if err != nil {
		return err
	}

	a.Token = token

	switch cfg.TokenStore.(type) {
	case http.Header:
		cfg.ResponseWriter.Header().Add("Authorization", "Bearer "+token)

	case http.Cookie:
		http.SetCookie(cfg.ResponseWriter, &http.Cookie{
			Name:     apiAccessCookie,
			Value:    token,
			Expires:  exp,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.SecureCookie,
		})

	default:
		return fmt.Errorf("%s", "unrecognized token store")
	}

	return nil
}
