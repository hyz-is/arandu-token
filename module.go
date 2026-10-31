// Package token is an Arandu module for the authentication of native apps: a
// token per person and per device, with renewal and revocation.
//
// A device signs in with whatever the application asks of it, a password and a
// second factor, and the application then calls Service.Issue. The device gets a
// Pair: a short-lived access token it sends as Authorization: Bearer on every
// request, and a long-lived refresh token it exchanges for the next pair. Both
// are opaque random strings with a readable prefix, and the store keeps only the
// SHA-256 digest of each. A refresh token is good once: exchanging it rotates the
// pair, and presenting one that was already exchanged is taken for theft and
// revokes the whole session of that device.
//
// The files are laid out by role, so the package reads top to bottom:
//
//	module.go   -> registration, schedule, health and migrations
//	config.go   -> what the application passes in
//	service.go  -> issue, refresh, resolve, switch, revoke, list and clean
//	http.go     -> the Bearer middleware and the context helpers
//	limiter.go  -> the throttle for sign-in, with a progressive lockout
//	secret.go   -> Secret, Pair and Revealed: tokens that do not print
//	events.go   -> what the application records
//	errors.go   -> the errors, each with the status the router answers it
//	model.go    -> Device, Principal, Digest and the validation of identifiers
//	actions.go  -> the one action the schedule runs under
//
// The module does not know users. It stores an identifier, never checks a
// password, and never decides a tenant of data: the workspace it keeps beside a
// token is a candidate that the application revalidates against the membership
// on every request, and the Grant that carries the tenant is the application's.
//
// An application registers it explicitly. There is no service provider, no
// container and no discovery: the wiring is the lines somebody wrote, and
// reading them is how they learn what the application is made of.
package token

import (
	"context"
	"fmt"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/database/schema"
)

// Module is what the application registers.
//
// It implements foundation.Module, which is Name and Routes and nothing else,
// and the optional interfaces for what it owns: Migratable for its tables,
// Schedulable for the clean of expired credentials, and Health for the storage
// it depends on. It registers no route: the sign-in, the refresh and the
// sign-out of a native app are the application's own endpoints, because they
// check the application's passwords and answer in the application's shape.
type Module struct {
	svc *Service
	cfg Config
}

// Compile-time proof that the module honors the contracts it claims.
var (
	_ foundation.Module      = (*Module)(nil)
	_ foundation.Migratable  = (*Module)(nil)
	_ foundation.Schedulable = (*Module)(nil)
	_ foundation.Health      = (*Module)(nil)
)

// New returns the module, or the reason it cannot be built.
//
// The collaborators are parameters and not fields somebody fills in afterwards:
// a module that could be registered half-wired is a module whose first request
// is the thing that reports the missing half. It returns an error rather than
// panicking, because everything it refuses is a wiring mistake, and a wiring
// mistake found at boot costs one restart.
func New(cfg Config, db *data.DB) (*Module, error) {
	svc, err := NewService(cfg, db)
	if err != nil {
		return nil, err
	}
	return &Module{svc: svc, cfg: svc.cfg}, nil
}

// Name is the module identifier: a lowercase slug, stable, no spaces.
func (m *Module) Name() string { return "token" }

// Routes registers nothing. The module has no endpoint of its own; it is
// registered so that its migrations, its schedule and its health check are
// collected.
func (m *Module) Routes(*fhttp.Router) {}

// Service is the service the application calls: Issue, Refresh, Resolve,
// Switch, the revocations, ListDevices and Clean, and the middleware.
func (m *Module) Service() *Service { return m.svc }

// Schedule declares the daily clean of expired and revoked credentials.
//
// The clean is not optional: a credentials table nobody cleans grows by two
// rows for every refresh of every device, forever. Config.CleanSpec moves it,
// and CleanDisabled turns the schedule off for an application that calls
// Service.Clean from its own.
func (m *Module) Schedule() []foundation.Task {
	if m.cfg.CleanSpec == CleanDisabled {
		return nil
	}
	return []foundation.Task{{
		ID:        "token.credentials.clean",
		Spec:      m.cfg.CleanSpec,
		Scope:     foundation.Global,
		Timeout:   10 * time.Minute,
		Singleton: true,
		Action:    TokenClean,
		Run: func(ctx context.Context, _ security.Grant) error {
			_, err := m.svc.Clean(ctx)
			return err
		},
	}}
}

// Health reports whether the tables are there and the database answers.
func (m *Module) Health(ctx context.Context) error {
	for _, table := range []string{credentialsTable, devicesTable} {
		rows, err := m.svc.db.QueryContext(ctx, `SELECT 1 FROM `+table+` WHERE 1 = 0`)
		if err != nil {
			return fmt.Errorf("token: %s is not readable (has `aru migrate` run?): %w", table, err)
		}
		_ = rows.Close()
	}
	return nil
}

// Migrations declares the schema this module owns.
//
// They are returned in the order their names sort in, which is the order they
// apply in: the name carries the order, and nothing else decides it.
func (m *Module) Migrations() []foundation.Migration {
	return []foundation.Migration{createTokenTables{}}
}

// The migration is reversible, and the assertion is here rather than discovered
// at rollback: the migrator tests for Down with a type assertion, so a Down
// with the wrong signature would leave a rollback that silently does nothing.
var _ migrations.ReversibleMigration = createTokenTables{}

// createTokenTables is the two tables this module owns.
type createTokenTables struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order. It is fixed
// once the package is published: changing what an applied name means leaves the
// change missing everywhere it already ran, and nothing says so.
func (createTokenTables) GetName() string { return "20261031_0001_create_token_tables" }

// Up creates the credentials and the devices.
//
// Every instant is written by Go and has no database default. The digest is a
// SHA-256 in hexadecimal, 64 characters, and the one index every request reads
// by. revoked_reason is what tells a refresh token that was exchanged, whose
// reuse is theft, from one that was revoked, whose use is only refused.
func (createTokenTables) Up(ctx context.Context, conn migrations.Connection) error {
	if err := conn.Schema().Create(ctx, credentialsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("digest", 64)
		table.String("kind", 16)
		table.String("family_id", maxIdentifierLen)
		table.String("user_id", maxIdentifierLen)
		table.String("workspace_id", maxIdentifierLen)
		table.String("device_id", maxIdentifierLen)
		table.Timestamp("expires_at")
		table.Timestamp("last_used_at").Nullable()
		table.Timestamp("revoked_at").Nullable()
		table.String("revoked_reason", 32).Nullable()
		table.Timestamp("created_at")

		table.Unique([]string{"digest"}, "token_credentials_digest_unique")
		table.Index([]string{"family_id"}, "token_credentials_family_idx")
		table.Index([]string{"user_id", "device_id"}, "token_credentials_user_device_idx")
		table.Index([]string{"expires_at"}, "token_credentials_expires_idx")
		table.Index([]string{"revoked_at"}, "token_credentials_revoked_idx")
	}); err != nil {
		return err
	}
	return conn.Schema().Create(ctx, devicesTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("user_id", maxIdentifierLen)
		table.String("device_id", maxIdentifierLen)
		table.String("name", maxNameLen)
		table.String("platform", maxPlatformLen)
		table.String("last_ip", maxIPLen)
		table.Timestamp("last_used_at")
		table.Timestamp("created_at")
		table.Timestamp("updated_at")

		table.Unique([]string{"user_id", "device_id"}, "token_devices_user_device_unique")
		table.Index([]string{"updated_at"}, "token_devices_updated_idx")
	})
}

// Down drops both tables, and their indexes with them.
func (createTokenTables) Down(ctx context.Context, conn migrations.Connection) error {
	if err := conn.Schema().DropIfExists(ctx, devicesTable); err != nil {
		return err
	}
	return conn.Schema().DropIfExists(ctx, credentialsTable)
}
