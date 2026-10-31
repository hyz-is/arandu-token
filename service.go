package token

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/hesape/database"
)

// Service issues, exchanges, resolves and revokes the tokens of native apps.
//
// It is the only owner of the database handle. It keeps no token: it hands each
// one back once, in the Pair that issues it, and stores the SHA-256 digest.
//
// # Why it reads its tables without a Grant
//
// Every other module of the ecosystem reaches its rows through a Grant,
// because a row belongs to a tenant and the Grant names it. A credential cannot
// work that way. The question Resolve answers is who is asking, which comes
// before any Grant exists, and the only thing the caller holds is the token:
// the token is what says which user and which workspace. The session store of
// hesape reads its table the same way and for the same reason, keyed by the
// secret and by nothing else.
//
// Nothing here decides a tenant of data. The workspace stored with a token is a
// candidate that the application revalidates against the membership on every
// request, and only the Grant it issues afterwards carries a tenant.
//
// # What it does not do
//
// It does not know users. It does not check a password or a second factor, and
// it never decides whether somebody may sign in: the application does, and then
// asks for a pair. Who may list or revoke whose devices is the application's
// too; every method here takes the user it acts on, and a caller that passes
// somebody else's has already made the mistake.
type Service struct {
	db  *data.DB
	cfg Config
}

// NewService returns the service over the application's database handle, or the
// reason it cannot be built. Most applications get it from Module.Service.
func NewService(cfg Config, db *data.DB) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errNilDatabase
	}
	return &Service{db: db, cfg: cfg.withDefaults()}, nil
}

// now is the current instant in UTC at the resolution the tables keep: a
// microsecond, which is what PostgreSQL stores.
func (s *Service) now() time.Time { return s.cfg.Clock().UTC().Truncate(time.Microsecond) }

// Issue signs a device in: it gives the device a new pair bound to the
// workspace, and ends any session that device already had.
//
// The application has already proved who the user is, with a password and a
// second factor if it asks for one, and that the user belongs to the workspace.
// workspaceID may be empty for a session bound to none yet, which Switch binds
// later. The address of the request, when the context carries one through
// WithClientIP, is recorded on the device.
func (s *Service) Issue(ctx context.Context, userID, workspaceID string, device Device) (Pair, error) {
	if err := checkID("user ID", userID, true); err != nil {
		return Pair{}, err
	}
	if err := checkID("workspace ID", workspaceID, false); err != nil {
		return Pair{}, err
	}
	device, err := checkDevice(device)
	if err != nil {
		return Pair{}, err
	}
	now, ip := s.now(), clientIP(ctx)

	if err := s.saveDevice(ctx, userID, device, ip, now); err != nil {
		return Pair{}, err
	}
	family, err := data.NewID()
	if err != nil {
		return Pair{}, err
	}

	var pair Pair
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		// A device has one session: signing in again on it ends the one it had.
		if _, err := s.endSessions(ctx, now, ReasonReplaced, ip, `user_id = ? AND device_id = ?`, userID, device.ID); err != nil {
			return err
		}
		var err error
		pair, err = s.insertPair(ctx, now, family, userID, workspaceID, device.ID)
		if err != nil {
			return err
		}
		return s.record(ctx, Event{Kind: EventIssued, UserID: userID, WorkspaceID: workspaceID, DeviceID: device.ID, FamilyID: family, IP: ip, At: now})
	})
	if err != nil {
		return Pair{}, err
	}
	return pair, nil
}

// Refresh exchanges a refresh token for a new pair, and the token it was given
// stops working.
//
// The new pair belongs to the same session and the same workspace. Exactly one
// of two simultaneous calls with the same token wins; the other presented a
// token that had already been exchanged.
//
// A refresh token that was already exchanged is a reuse: either the owner or a
// thief holds a copy, and there is no telling which. Refresh revokes every
// credential of the session, records EventReuseDetected and answers
// ErrReuseDetected, and the device has to sign in again. When Config.ReuseGrace
// is set, a reuse that comes within it is refused as ErrInvalidToken and
// revokes nothing.
//
// A token that was never issued, expired, revoked, or is an access token, is
// ErrInvalidToken.
func (s *Service) Refresh(ctx context.Context, refresh string) (Pair, error) {
	if !strings.HasPrefix(refresh, s.cfg.RefreshPrefix) {
		return Pair{}, ErrInvalidToken
	}
	digest := DigestOf(refresh).String()
	now, ip := s.now(), clientIP(ctx)

	var (
		pair  Pair
		reuse bool
	)
	err := data.Transaction(ctx, s.db, func(ctx context.Context) error {
		// The exchange is one conditional statement. Of two calls with the same
		// token, the database lets one change the row; the other changes
		// nothing, and finds the row already rotated when it looks.
		won, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?, last_used_at = ?
			WHERE digest = ? AND kind = ? AND revoked_at IS NULL AND expires_at > ?`,
			now, reasonRotated, now, digest, kindRefresh, now)
		if err != nil {
			return err
		}
		row, found, err := s.byDigest(ctx, digest)
		if err != nil {
			return err
		}
		if !found || row.kind != kindRefresh {
			return ErrInvalidToken
		}

		if won == 0 {
			if row.revokedReason != reasonRotated || !row.revokedAt.Valid {
				return ErrInvalidToken
			}
			if s.cfg.ReuseGrace > 0 && now.Sub(row.revokedAt.Time) <= s.cfg.ReuseGrace {
				return ErrInvalidToken
			}
			if _, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?
				WHERE family_id = ? AND revoked_at IS NULL`, now, ReasonReuse, row.familyID); err != nil {
				return err
			}
			reuse = true
			return s.record(ctx, Event{Kind: EventReuseDetected, UserID: row.userID, WorkspaceID: row.workspaceID, DeviceID: row.deviceID, FamilyID: row.familyID, Reason: ReasonReuse, IP: ip, At: now})
		}

		// The access token the old pair carried goes with it: a copy of it that
		// somebody else holds does not outlive the exchange.
		if _, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?
			WHERE family_id = ? AND kind = ? AND revoked_at IS NULL`, now, reasonRotated, row.familyID, kindAccess); err != nil {
			return err
		}
		pair, err = s.insertPair(ctx, now, row.familyID, row.userID, row.workspaceID, row.deviceID)
		if err != nil {
			return err
		}
		if err := s.touchDevice(ctx, row.userID, row.deviceID, ip, now); err != nil {
			return err
		}
		return s.record(ctx, Event{Kind: EventRefreshed, UserID: row.userID, WorkspaceID: row.workspaceID, DeviceID: row.deviceID, FamilyID: row.familyID, IP: ip, At: now})
	})
	if err != nil {
		return Pair{}, err
	}
	if reuse {
		return Pair{}, ErrReuseDetected
	}
	return pair, nil
}

// Resolve answers who a valid access token was issued to.
//
// ok is false for a digest that was never issued, expired, was revoked, or
// belongs to a refresh token, and the four are not told apart. The error is for
// the store failing to answer, which is not the same thing as the token being
// refused and must not be turned into a 401.
//
// It records the use at the resolution of Config.TouchInterval, on the token
// and on its device, with the address WithClientIP put on the context. A
// failure to record the use does not refuse a token that is good.
func (s *Service) Resolve(ctx context.Context, digest Digest) (Principal, bool, error) {
	now := s.now()
	var (
		p    Principal
		id   string
		last sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, workspace_id, device_id, family_id, last_used_at
		FROM `+credentialsTable+` WHERE digest = ? AND kind = ? AND revoked_at IS NULL AND expires_at > ?`,
		digest.String(), kindAccess, now).Scan(&id, &p.UserID, &p.WorkspaceID, &p.DeviceID, &p.FamilyID, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, false, nil
	}
	if err != nil {
		return Principal{}, false, fmt.Errorf("token: reading a credential: %w", err)
	}

	interval := s.cfg.TouchInterval
	if interval < 0 || !last.Valid || now.Sub(last.Time) >= interval {
		cutoff := now.Add(-interval)
		if interval < 0 {
			cutoff = now.Add(time.Microsecond)
		}
		// The use is written only when this call is the one that moved the
		// stamp, so a burst of requests writes once. A failure here is the
		// bookkeeping failing, not the token: the next read says if the store is
		// down.
		if n, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET last_used_at = ?
			WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`, now, id, cutoff); err == nil && n == 1 {
			_ = s.touchDevice(ctx, p.UserID, p.DeviceID, clientIP(ctx), now)
		}
	}
	return p, true, nil
}

// Switch moves the session of an access token to another workspace: it revokes
// that session and issues a new pair bound to workspaceID, on the same device.
//
// The application checks before calling it that the user belongs to the
// workspace. The module only stores the candidate; the Membership is checked
// again on every request that uses the new token.
//
// The old pair, refresh token included, stops working, so a client that keeps
// using it is refused. A token that is not a valid access token is
// ErrInvalidToken.
func (s *Service) Switch(ctx context.Context, access, workspaceID string) (Pair, error) {
	if err := checkID("workspace ID", workspaceID, false); err != nil {
		return Pair{}, err
	}
	if !strings.HasPrefix(access, s.cfg.AccessPrefix) {
		return Pair{}, ErrInvalidToken
	}
	digest := DigestOf(access).String()
	now, ip := s.now(), clientIP(ctx)
	family, err := data.NewID()
	if err != nil {
		return Pair{}, err
	}

	var pair Pair
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		row, found, err := s.byDigest(ctx, digest)
		if err != nil {
			return err
		}
		if !found || row.kind != kindAccess || row.revokedAt.Valid || !row.expiresAt.After(now) {
			return ErrInvalidToken
		}
		// Of two switches with the same token, one revokes it and the other
		// finds it revoked.
		won, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?
			WHERE id = ? AND revoked_at IS NULL`, now, ReasonSwitched, row.id)
		if err != nil {
			return err
		}
		if won == 0 {
			return ErrInvalidToken
		}
		if _, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?
			WHERE family_id = ? AND revoked_at IS NULL`, now, ReasonSwitched, row.familyID); err != nil {
			return err
		}
		pair, err = s.insertPair(ctx, now, family, row.userID, workspaceID, row.deviceID)
		if err != nil {
			return err
		}
		if err := s.touchDevice(ctx, row.userID, row.deviceID, ip, now); err != nil {
			return err
		}
		return s.record(ctx, Event{Kind: EventSwitched, UserID: row.userID, WorkspaceID: workspaceID, PreviousWorkspaceID: row.workspaceID, DeviceID: row.deviceID, FamilyID: family, IP: ip, At: now})
	})
	if err != nil {
		return Pair{}, err
	}
	return pair, nil
}

// Revoke ends the session a token belongs to: an access token or a refresh
// token, and both of its pair and every earlier pair of the same sign-in.
//
// It is the device signing out. It is idempotent: a token that is unknown or
// already revoked is not an error, so a client can retry a sign-out that timed
// out.
func (s *Service) Revoke(ctx context.Context, token string) error {
	if !strings.HasPrefix(token, s.cfg.AccessPrefix) && !strings.HasPrefix(token, s.cfg.RefreshPrefix) {
		return nil
	}
	digest := DigestOf(token).String()
	now, ip := s.now(), clientIP(ctx)

	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		row, found, err := s.byDigest(ctx, digest)
		if err != nil || !found {
			return err
		}
		_, err = s.endSessions(ctx, now, ReasonSignedOut, ip, `family_id = ?`, row.familyID)
		return err
	})
}

// RevokeDevice ends the session of one of the user's devices.
//
// It is scoped to the user: a device ID that belongs to somebody else, or that
// has no live session, is ErrNotFound.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	if err := checkID("user ID", userID, true); err != nil {
		return err
	}
	if err := checkID("device ID", deviceID, true); err != nil {
		return err
	}
	now, ip := s.now(), clientIP(ctx)

	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		ended, err := s.endSessions(ctx, now, ReasonDeviceRemoved, ip, `user_id = ? AND device_id = ?`, userID, deviceID)
		if err != nil {
			return err
		}
		if ended == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RevokeAllForUser ends every session of the user, on every device, and answers
// how many it ended. It is what a password change, a suspension or "sign out
// everywhere" calls.
func (s *Service) RevokeAllForUser(ctx context.Context, userID string) (int, error) {
	if err := checkID("user ID", userID, true); err != nil {
		return 0, err
	}
	now, ip := s.now(), clientIP(ctx)

	var ended int
	err := data.Transaction(ctx, s.db, func(ctx context.Context) error {
		var err error
		ended, err = s.endSessions(ctx, now, ReasonAllDevices, ip, `user_id = ?`, userID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return ended, nil
}

// ListDevices returns the devices of the user that have a live session, the
// most recently used first.
//
// A device whose session was revoked or whose refresh token expired is not
// listed: it cannot get in, and it is not a place the user is signed in.
func (s *Service) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	if err := checkID("user ID", userID, true); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.device_id, d.name, d.platform, d.last_used_at, d.last_ip, d.created_at
		FROM `+devicesTable+` d
		WHERE d.user_id = ? AND EXISTS (
			SELECT 1 FROM `+credentialsTable+` c
			WHERE c.user_id = d.user_id AND c.device_id = d.device_id
				AND c.kind = ? AND c.revoked_at IS NULL AND c.expires_at > ?)
		ORDER BY d.last_used_at DESC, d.device_id`, userID, kindRefresh, s.now())
	if err != nil {
		return nil, fmt.Errorf("token: listing devices: %w", err)
	}
	defer rows.Close()

	devices := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.LastUsedAt, &d.LastIP, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("token: reading a device: %w", err)
		}
		d.LastUsedAt, d.CreatedAt = d.LastUsedAt.UTC(), d.CreatedAt.UTC()
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("token: listing devices: %w", err)
	}
	return devices, nil
}

// Clean deletes the tokens that expired or were revoked longer ago than
// Config.Retention, and then the devices that have no token left and have not
// been seen since. The module schedules it daily; an application that disabled
// the schedule calls it from its own.
//
// Tokens inside the retention are kept on purpose: a refresh token that was
// exchanged is how a reuse is recognised, and it has to outlive the exchange.
func (s *Service) Clean(ctx context.Context) (Cleaned, error) {
	cutoff := s.now().Add(-s.cfg.Retention)
	var out Cleaned
	var err error

	out.Credentials, err = s.exec(ctx, `DELETE FROM `+credentialsTable+` WHERE expires_at < ? OR revoked_at < ?`, cutoff, cutoff)
	if err != nil {
		return Cleaned{}, err
	}
	out.Devices, err = s.exec(ctx, `DELETE FROM `+devicesTable+` WHERE updated_at < ? AND NOT EXISTS (
		SELECT 1 FROM `+credentialsTable+` c WHERE c.user_id = `+devicesTable+`.user_id AND c.device_id = `+devicesTable+`.device_id)`, cutoff)
	if err != nil {
		return Cleaned{}, err
	}
	return out, nil
}

// credential is a row of the credentials table, without its digest.
type credential struct {
	id            string
	kind          string
	familyID      string
	userID        string
	workspaceID   string
	deviceID      string
	expiresAt     time.Time
	revokedAt     sql.NullTime
	revokedReason string
}

// byDigest reads the row a digest names, whatever its state.
func (s *Service) byDigest(ctx context.Context, digest string) (credential, bool, error) {
	var (
		c      credential
		reason sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, family_id, user_id, workspace_id, device_id, expires_at, revoked_at, revoked_reason
		FROM `+credentialsTable+` WHERE digest = ?`, digest).
		Scan(&c.id, &c.kind, &c.familyID, &c.userID, &c.workspaceID, &c.deviceID, &c.expiresAt, &c.revokedAt, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return credential{}, false, nil
	}
	if err != nil {
		return credential{}, false, fmt.Errorf("token: reading a credential: %w", err)
	}
	c.revokedReason = reason.String
	return c, true, nil
}

// session is one sign-in of one device, as the events name it.
type session struct{ familyID, userID, workspaceID, deviceID string }

// endSessions revokes every live credential the condition selects, records one
// EventRevoked for each session it ended, and answers how many sessions that
// was. The condition is a fixed fragment written in this file; the values are
// arguments.
func (s *Service) endSessions(ctx context.Context, now time.Time, reason, ip, condition string, args ...any) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT family_id, user_id, workspace_id, device_id
		FROM `+credentialsTable+` WHERE revoked_at IS NULL AND expires_at > ? AND (`+condition+`)`,
		append([]any{now}, args...)...)
	if err != nil {
		return 0, fmt.Errorf("token: reading sessions: %w", err)
	}
	var sessions []session
	for rows.Next() {
		var x session
		if err := rows.Scan(&x.familyID, &x.userID, &x.workspaceID, &x.deviceID); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("token: reading a session: %w", err)
		}
		sessions = append(sessions, x)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("token: reading sessions: %w", err)
	}
	if len(sessions) == 0 {
		return 0, nil
	}

	if _, err := s.exec(ctx, `UPDATE `+credentialsTable+` SET revoked_at = ?, revoked_reason = ?
		WHERE revoked_at IS NULL AND (`+condition+`)`, append([]any{now, reason}, args...)...); err != nil {
		return 0, err
	}
	for _, x := range sessions {
		if err := s.record(ctx, Event{Kind: EventRevoked, UserID: x.userID, WorkspaceID: x.workspaceID, DeviceID: x.deviceID, FamilyID: x.familyID, Reason: reason, IP: ip, At: now}); err != nil {
			return 0, err
		}
	}
	return len(sessions), nil
}

// insertPair writes an access token and a refresh token of one session and
// returns them.
func (s *Service) insertPair(ctx context.Context, now time.Time, family, userID, workspaceID, deviceID string) (Pair, error) {
	access, accessDigest, err := s.mint(s.cfg.AccessPrefix)
	if err != nil {
		return Pair{}, err
	}
	refresh, refreshDigest, err := s.mint(s.cfg.RefreshPrefix)
	if err != nil {
		return Pair{}, err
	}
	pair := Pair{
		Access: newSecret(access), Refresh: newSecret(refresh),
		AccessExpires: now.Add(s.cfg.AccessTTL), RefreshExpires: now.Add(s.cfg.RefreshTTL),
		WorkspaceID: workspaceID, DeviceID: deviceID, accessTTL: s.cfg.AccessTTL,
	}
	for _, c := range []struct {
		digest, kind string
		expires      time.Time
	}{{accessDigest, kindAccess, pair.AccessExpires}, {refreshDigest, kindRefresh, pair.RefreshExpires}} {
		id, err := database.NewOrderedID()
		if err != nil {
			return Pair{}, err
		}
		if _, err := s.exec(ctx, `INSERT INTO `+credentialsTable+`
			(id, digest, kind, family_id, user_id, workspace_id, device_id, expires_at, last_used_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, c.digest, c.kind, family, userID, workspaceID, deviceID, c.expires, now, now); err != nil {
			return Pair{}, err
		}
	}
	return pair, nil
}

// mint makes a token and its digest. A token is the prefix and 32 random bytes
// from the operating system, in base64url: 256 bits, which is why a fast hash
// is the right digest for it.
func (s *Service) mint(prefix string) (token, digest string, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("token: reading random bytes: %w", err)
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(raw[:])
	return token, DigestOf(token).String(), nil
}

// saveDevice writes the device of a sign-in: it updates the row of this user's
// device, and inserts it the first time. Two sign-ins of one new device that
// race both end with the row.
func (s *Service) saveDevice(ctx context.Context, userID string, d Device, ip string, now time.Time) error {
	update := func() (int64, error) {
		return s.exec(ctx, `UPDATE `+devicesTable+` SET name = ?, platform = ?, last_ip = ?, last_used_at = ?, updated_at = ?
			WHERE user_id = ? AND device_id = ?`, d.Name, d.Platform, ip, now, now, userID, d.ID)
	}
	n, err := update()
	if err != nil || n > 0 {
		return err
	}
	id, err := database.NewOrderedID()
	if err != nil {
		return err
	}
	_, err = s.exec(ctx, `INSERT INTO `+devicesTable+`
		(id, user_id, device_id, name, platform, last_ip, last_used_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, userID, d.ID, d.Name, d.Platform, ip, now, now, now)
	if errors.Is(err, database.ErrUniqueViolation) {
		_, err = update()
	}
	return err
}

// touchDevice records a use of a device: when, and from where when the address
// is known.
func (s *Service) touchDevice(ctx context.Context, userID, deviceID, ip string, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE `+devicesTable+`
		SET last_used_at = ?, updated_at = ?, last_ip = CASE WHEN ? = '' THEN last_ip ELSE ? END
		WHERE user_id = ? AND device_id = ?`, now, now, ip, ip, userID, deviceID)
	return err
}

// record hands an event to the application's recorder, if it has one.
func (s *Service) record(ctx context.Context, e Event) error {
	if s.cfg.Events == nil {
		return nil
	}
	if err := s.cfg.Events.Record(ctx, e); err != nil {
		return fmt.Errorf("token: recording %s: %w", e.Kind, err)
	}
	return nil
}

// exec runs a statement and answers how many rows it changed.
func (s *Service) exec(ctx context.Context, query string, args ...any) (int64, error) {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("token: %w", err)
	}
	return n, nil
}
