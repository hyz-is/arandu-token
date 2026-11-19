package feature_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	hedatabase "github.com/arandu-io/hesape/database"
	pgxconnector "github.com/arandu-io/hesape/database/connectors/pgx"
	"github.com/arandu-io/hesape/database/migrations"

	token "github.com/hyz-is/arandu-token"
)

// A database migrated before the framework's default time precision was
// microseconds holds the instants of both tables in whole seconds, and the last
// migration widens them in place. On SQLite there is nothing to widen, and
// every other test of this suite applies it there.

const widenName = "20261119_0001_widen_token_time_precision"

// instants are the date-time columns of each table.
var instants = map[string][]string{
	"token_credentials": {"expires_at", "last_used_at", "revoked_at", "created_at"},
	"token_devices":     {"last_used_at", "created_at", "updated_at"},
}

func TestTheLastMigrationWidensTheTokenTables(t *testing.T) {
	all := (&token.Module{}).Migrations()
	widen, ok := all[len(all)-1].(migrations.WidenTimePrecision)
	if !ok || widen.GetName() != widenName || len(widen.Tables) != 2 ||
		widen.Tables[0] != "token_credentials" || widen.Tables[1] != "token_devices" {
		t.Fatalf("the last migration is %s, want the widening of both token tables", all[len(all)-1].GetName())
	}
}

func TestTheTokenTablesAreWidenedOnPostgres(t *testing.T) {
	dsn := os.Getenv(postgresDSN)
	if dsn == "" {
		t.Skip("no server: set " + postgresDSN)
	}
	ctx := context.Background()
	suffix := make([]byte, 8)
	_, _ = rand.Read(suffix)
	schema := "token_widen_" + hex.EncodeToString(suffix)

	admin, err := sql.Open(pgxconnector.PostgresConnector{}.DriverName(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := sql.Open(pgxconnector.PostgresConnector{}.DriverName(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	conn := hedatabase.ForMigrations(hedatabase.NewConnection(pool, schema, "", map[string]any{"driver": "pgsql", "name": "token-widen-test"}))
	all := (&token.Module{}).Migrations()
	for _, migration := range all[:len(all)-1] {
		if err := migration.Up(ctx, conn); err != nil {
			t.Fatalf("applying %s: %v", migration.GetName(), err)
		}
	}
	// The shape a release before the widening left on a database migrated
	// while the default was whole seconds.
	for table, columns := range instants {
		for _, column := range columns {
			if _, err := pool.ExecContext(ctx, `ALTER TABLE `+table+` ALTER COLUMN `+column+` TYPE timestamp(0) without time zone`); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertCredential := `INSERT INTO token_credentials
		(id, digest, kind, family_id, user_id, workspace_id, device_id, expires_at, last_used_at, revoked_at, revoked_reason, created_at)
		VALUES ($1, $2, 'access', 'fam', 'ana', 'ws-1', 'phone-1', $3, $3, $3, 'x', $3)`
	insertDevice := `INSERT INTO token_devices
		(id, user_id, device_id, name, platform, last_ip, last_used_at, created_at, updated_at)
		VALUES ($1, 'ana', $2, 'phone', 'ios', '203.0.113.9', $3, $3, $3)`
	at := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	if _, err := pool.ExecContext(ctx, insertCredential, "cred-1", "digest-1", at); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, insertDevice, "dev-1", "phone-1", at); err != nil {
		t.Fatal(err)
	}

	if err := all[len(all)-1].Up(ctx, conn); err != nil {
		t.Fatalf("widening: %v", err)
	}
	var narrow int
	if err := pool.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type LIKE 'timestamp%' AND datetime_precision < 6`).Scan(&narrow); err != nil {
		t.Fatal(err)
	}
	if narrow != 0 {
		t.Fatalf("%d date-time columns are still in seconds after the widening", narrow)
	}
	// New connections, as a deploy has after it migrates: one that prepared a
	// statement over the narrow columns is refused its cached plan.
	pool.SetMaxIdleConns(0)
	pool.SetMaxIdleConns(2)

	var created time.Time
	if err := pool.QueryRowContext(ctx, `SELECT created_at FROM token_credentials WHERE id = $1`, "cred-1").Scan(&created); err != nil {
		t.Fatal(err)
	}
	if !created.UTC().Equal(at) {
		t.Fatalf("the credential from before the widening was created at %s, want %s", created.UTC(), at)
	}
	// Rows written after the widening keep their instants to the microsecond.
	precise := at.Add(time.Second + 123456*time.Microsecond)
	if _, err := pool.ExecContext(ctx, insertCredential, "cred-2", "digest-2", precise); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, insertDevice, "dev-2", "phone-2", precise); err != nil {
		t.Fatal(err)
	}
	for table, columns := range instants {
		id := map[string]string{"token_credentials": "cred-2", "token_devices": "dev-2"}[table]
		for _, column := range columns {
			var read time.Time
			if err := pool.QueryRowContext(ctx, `SELECT `+column+` FROM `+table+` WHERE id = $1`, id).Scan(&read); err != nil {
				t.Fatal(err)
			}
			if !read.UTC().Equal(precise) {
				t.Errorf("%s.%s reads back %s, want %s", table, column, read.UTC(), precise)
			}
		}
	}
	if reversible, ok := all[len(all)-1].(migrations.ReversibleMigration); !ok {
		t.Fatal("the widening cannot be rolled back")
	} else if err := reversible.Down(ctx, conn); err != nil {
		t.Fatalf("rolling the widening back: %v", err)
	}
}
