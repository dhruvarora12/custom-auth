package middleware

import (
	"net/http"
	"strings"

	"auth-service/internal/auth"
)

func RequireAuth(tokens *auth.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.Header.Get("Authorization")
			if !strings.HasPrefix(v, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(v, "Bearer ")

			if tokens.IsBlacklisted(r.Context(), tokenStr) {
				http.Error(w, `{"error":"token revoked"}`, http.StatusUnauthorized)
				return
			}

			claims, err := tokens.Verify(tokenStr)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			ctx := auth.ContextWithUserID(r.Context(), claims.RegisteredClaims.Subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
