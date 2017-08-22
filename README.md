# access
Ponzu Addon to manage API access grants and tokens for authentication

### Usage

```go
package content

type User struct {
    Email string `json:"email"`
    AccountStatus string `json:"account_status"`
}

import 	(
    "github.com/bosssauce/access"
    // ...
)

// create a grand for a user
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

    fmt.Println(
        fmt.Sprintf(
            "The access token for user (%s) is: %s",
            grant.Email, grant.Token,
        ),
    )

    return nil
}
```