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

    func (u *User) BeforeAPICreate()
```