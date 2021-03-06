# access
[Ponzu](https://ponzu-cms.org) Addon to manage API access grants and tokens for authentication

### Installation:
```bash
$ ponzu add github.com/bosssauce/access
```

## Usage

```go
// content/user.go
package content

import (
	"github.com/bosssauce/access"
	// ...
)

type User struct {
    // ... 
	Email         string `json:"email"`
	AccountStatus string `json:"account_status"`
}

// create a grant for a user after one has been created via API call
func (u *User) AfterAPICreate(res http.ResponseWriter, req *http.Request) error {
	// create an access configuration including the duration after which the
	// token will expire, the ResponseWriter to write the token to, and which
	// of the req.Header or req.Cookie{}
	cfg := &access.Config{
		ExpireAfter:    time.Hour * 24 * 7,
		ResponseWriter: res,
		TokenStore:     req.Header,
	}

	// Grant access to the user based on the request
	grant, err := access.Grant(u.Email, req.PostFormValue("password"), cfg)
	if err != nil {
		return err
	}

	fmt.Printf(
		"The access token for user (%s) is: %s\n",
		grant.Key, grant.Token,
	)

	return nil
}
```

#### *Then, from other content type files:*

```go
// content/private_event.go
package content

import (
	"github.com/bosssauce/access"
	// ...
)

type PrivateEvent struct {
	// ...
	OrganizerEmail string
	Location       string
	Duration       int
	Rsvps          []string
}

func (e *PrivateEvent) BeforeAPICreate(res http.ResponseWriter, req *http.Request) error {
	if !access.IsGranted(req, req.Header) {
		return fmt.Errorf(
			"no access grant or valid token in request from: %s", 
			req.RemoteAddr,
		)
	}

	// request contains proper, valid token
	return nil
}

func (e *PrivateEvent) BeforeAPIUpdate(res http.ResponseWriter, req *http.Request) error {
	if !access.IsOwner(req, req.Header, e.OrganizerEmail) {
		return fmt.Errorf(
			"grant provided is not owner of PrivateEvent, from %s", 
			req.RemoteAddr,
		)
	}

	// request contains proper, valid token
	return nil
}
```


## Motivation

Some Ponzu content types need to be kept locked down and only accessible to
specific users or other owners. The `access` addon makes it easy to create a 
token-based access grant provided to a user, and then control the flow of data
output through Ponzu's content API through package methods like `access.IsGranted`
and `access.IsOwner`. Once a grant has been given to a request and returned via 
the response, the provided token is used to make follow-on requests for content 
which may be otherwise hidden, have omitted fields, or block create/update/delete operations. 

## API

`APIAccess` is the data for an API access grant
```go
type APIAccess struct {
	Email string `json:"email"`
	Hash  string `json:"hash"`
	Salt  string `json:"salt"`
	Token string `json:"token"`
}
```

`Config` contains settings for token creation and validation
```go
type Config struct {
	ExpireAfter    time.Duration
	ResponseWriter http.ResponseWriter
	TokenStore     reqHeaderOrHTTPCookie
	CustomClaims   map[string]interface{} // claims to add to your token
	SecureCookie   bool // optional, if using http.Cookie{} as TokenStore
}
```
- **Note:** The `TokenStore reqHeaderOrHTTPCookie` field within `Config` is an 
`interface{}` used to declare the means by which a token is sent and checked by 
the `access` addon. Setting it to the `req.Header` will add an `"Authorization: Beader $TOKEN"` 
header to the response, and alternatively setting the `TokenStore` to an `http.Cookie{}` 
will add the token in a cookie named `_apiAccessToken` to the response.


`Grant` creates a new APIAccess and saves it to the __apiAccess bucket in the database
and if an existing APIAccess grant is encountered in the database, Grant attempts
to update the grant but will fail if unauthorized
```go
func Grant(key, password string, cfg *Config) (*APIAccess, error)
```


`IsGranted` checks if the user request is authenticated by the token held within
the provided tokenStore (should be a http.Cookie or http.Header)
```go
func IsGranted(req *http.Request, tokenStore reqHeaderOrHTTPCookie) bool
```

`IsOwner` validates the access token and checks the claims within the
authenticated request's JWT for the key associated with the grant.
```go
func IsOwner(req *http.Request, tokenStore reqHeaderOrHTTPCookie, key string) bool
```
