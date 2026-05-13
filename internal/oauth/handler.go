package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/user"
	"github.com/redis/go-redis/v9"
)

type Handler struct {
	providers map[string]Provider
	users     *user.Repository
	tokens    *auth.TokenManager
	rdb       *redis.Client
}

func NewHandler(providers map[string]Provider, users *user.Repository, tokens *auth.TokenManager, rdb *redis.Client) *Handler {
	return &Handler{providers: providers, users: users, tokens: tokens, rdb: rdb}
}

func (h *Handler) Redirect(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := h.providers[providerName]
		state := randomHex()
		h.rdb.Set(r.Context(), "oauth:state:"+state, providerName, 10*time.Minute)
		http.Redirect(w, r, p.AuthURL(state), http.StatusTemporaryRedirect)
	}
}

func (h *Handler) Callback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		state := r.FormValue("state")
		code := r.FormValue("code")

		stored, err := h.rdb.GetDel(r.Context(), "oauth:state:"+state).Result()
		if err != nil || stored != providerName {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid state"})
			return
		}

		info, err := h.providers[providerName].ExchangeAndGetUser(r.Context(), code)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "oauth exchange failed"})
			return
		}

		// Apple sends name only on first login, via form_post user field
		if providerName == "apple" && info.Name == nil {
			if userJSON := r.FormValue("user"); userJSON != "" {
				var userData struct {
					Name struct {
						FirstName string `json:"firstName"`
						LastName  string `json:"lastName"`
					} `json:"name"`
				}
				if json.Unmarshal([]byte(userJSON), &userData) == nil {
					n := strings.TrimSpace(userData.Name.FirstName + " " + userData.Name.LastName)
					if n != "" {
						info.Name = &n
					}
				}
			}
		}

		u, err := h.users.FindOrCreateByOAuth(r.Context(), providerName, info.ProviderUserID, info.Email, info.Name, info.AvatarURL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get or create user"})
			return
		}

		pair, err := h.tokens.Issue(r.Context(), u.ID, u.Email)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token issuance failed"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"user": u, "tokens": pair})
	}
}

func randomHex() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
