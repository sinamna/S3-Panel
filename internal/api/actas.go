package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/snapp-incubator/S3-Panel/internal/auth"
	"github.com/snapp-incubator/S3-Panel/internal/control"
)

// identityKey is who a cached credential belongs to: the signed-in person, or
// the debug user they are acting as. Part of every credential cache key.
func identityKey(s auth.Session) string {
	if s.ActAs == "" {
		return s.Subject
	}
	return s.Subject + "|as:" + strings.ToLower(s.ActAs)
}

// actAsContext puts the session's act-as choice on the request context, where
// every control call picks it up (control.applyActAs). One middleware for the
// whole API group, so no route can forget it.
func (s *Server) actAsContext() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if session, ok := auth.SessionFrom(c); ok && session.ActAs != "" {
				req := c.Request()
				c.SetRequest(req.WithContext(control.WithActAs(req.Context(), session.ActAs)))
			}
			return next(c)
		}
	}
}

type actAsState struct {
	Available  bool                `json:"available"`
	Acting     string              `json:"acting,omitempty"`
	Candidates []control.DebugUser `json:"candidates"`
}

// candidates asks IAM which debug users this person may act as. Anything but a
// clean answer means "not available": IAM refuses non-admins and production.
func (s *Server) candidates(c echo.Context, session auth.Session) ([]control.DebugUser, bool) {
	if !session.IsRealAdmin(s.auth.AdminGroups()) {
		return nil, false
	}
	users, err := s.control.ListDebugUsers(c.Request().Context(), session.AccessToken)
	if err != nil {
		var ce *control.Error
		if !errors.As(err, &ce) {
			s.logger.Warn("could not list debug users", zap.Error(err))
		}
		return nil, false
	}
	return users, true
}

// handleActAsGet serves GET /act-as.
func (s *Server) handleActAsGet() echo.HandlerFunc {
	return func(c echo.Context) error {
		session, _ := auth.SessionFrom(c)
		users, ok := s.candidates(c, session)
		if users == nil {
			users = []control.DebugUser{}
		}
		return c.JSON(http.StatusOK, actAsState{Available: ok, Acting: session.ActAs, Candidates: users})
	}
}

// handleActAsSet serves POST /act-as {"email": "..."}.
func (s *Server) handleActAsSet() echo.HandlerFunc {
	return func(c echo.Context) error {
		session, _ := auth.SessionFrom(c)
		var body struct {
			Email string `json:"email"`
		}
		if err := c.Bind(&body); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}
		users, ok := s.candidates(c, session)
		if !ok {
			return echo.NewHTTPError(http.StatusForbidden, "acting as a debug user is not available")
		}
		target := ""
		for _, u := range users {
			if strings.EqualFold(u.Email, strings.TrimSpace(body.Email)) {
				target = u.Email
			}
		}
		if target == "" {
			return echo.NewHTTPError(http.StatusForbidden, "not a debug user")
		}
		return s.switchIdentity(c, session, target)
	}
}

// handleActAsClear serves DELETE /act-as.
func (s *Server) handleActAsClear() echo.HandlerFunc {
	return func(c echo.Context) error {
		session, _ := auth.SessionFrom(c)
		return s.switchIdentity(c, session, "")
	}
}

// switchIdentity leaves the current identity — revoking the console
// credentials it holds and dropping them from the cache — and saves the new
// choice in the session cookie.
func (s *Server) switchIdentity(c echo.Context, session auth.Session, target string) error {
	ctx := control.WithActAs(c.Request().Context(), session.ActAs)
	if err := s.control.RevokeSessions(ctx, session.AccessToken, s.Config.Server.Region, "console"); err != nil {
		s.logger.Warn("could not revoke credentials while switching identity", zap.Error(err))
	}
	s.credentials.dropIdentity(identityKey(session))
	session.ActAs = target
	if err := s.auth.Save(c, session); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not save the session")
	}
	return c.NoContent(http.StatusNoContent)
}
