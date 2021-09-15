## Different

Change the Message parameter of Unauthorized to ERROR type

## Example

``` golang

var A0001 = &Error{Code: "A0001", Err: errors.New("account not found")}

func login(account string) error {
	// do something...

	// if not found.
	return A0001
}


authMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
	Authenticator: func(c *gin.Context) (interface{}, error) {
		err := login()
		if err != nil {
			return nil,err
		}

	},
	Unauthorized: func(c *gin.Context, i int, e error) {
		c.JSON(200, e)
	},
})
```