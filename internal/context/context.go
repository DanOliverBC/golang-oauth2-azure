package ctx

import (
	"context"
)

type contextKey string

var contextKeyAuthtoken = contextKey("auth-token")

// SetToken sets the auth token in the context
func SetToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, contextKeyAuthtoken, token)
}

// GetToken gets the auth token from context
func GetToken(ctx context.Context) (string, bool) {
	tokenStr, ok := ctx.Value(contextKeyAuthtoken).(string)
	return tokenStr, ok
}
