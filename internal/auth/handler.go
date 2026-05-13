package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-service/internal/user"
)

type Handler struct {
	svc    *Service
	tokens *TokenManager
	users  *user.Repository
}

func NewHandler(svc *Service, tokens *TokenManager, users *user.Repository) *Handler {
	return &Handler{svc: svc, tokens: tokens, users: users}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Email == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	u, pair, err := h.svc.Register(r.Context(), RegisterInput{
		Email:    in.Email,
		Password: in.Password,
		Name:     in.Name,
	})
	if err != nil {
		if err == ErrEmailTaken {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "tokens": pair})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	u, pair, err := h.svc.Login(r.Context(), LoginInput{Email: in.Email, Password: in.Password})
	if err != nil {
		if err == ErrInvalidCredentials {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "tokens": pair})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	accessToken := extractBearer(r)
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	h.svc.Logout(r.Context(), accessToken, in.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}

	pair, err := h.svc.Refresh(r.Context(), in.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := h.users.FindByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}
	u, err := h.users.VerifyEmail(r.Context(), in.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}
	// Intentionally ignore error to prevent email enumeration
	h.svc.ForgotPassword(r.Context(), in.Email)
	writeJSON(w, http.StatusOK, map[string]string{"message": "if that email exists, a reset link has been sent"})
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Token == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "token and password required")
		return
	}
	if err := h.svc.ResetPassword(r.Context(), in.Token, in.Password); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "password reset successfully"})
}

func extractBearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
