package feature_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	hedatabase "github.com/arandu-io/hesape/database"
	pgxconnector "github.com/arandu-io/hesape/database/connectors/pgx"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"

	token "github.com/hyz-is/arandu-token"
)

// The sqlite DSN takes the write lock at the start of a transaction and waits
// for it, which is what makes two simultaneous transactions run one after the
// other instead of failing on an upgrade of the lock.
const sqliteOptions = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)"

// postgresDSN names a server for the suite to run against as well. Without it
// the Postgres half of every test is skipped, and the suite says so.
const postgresDSN = "ARANDU_TEST_POSTGRES_DSN"

// clock is a time source a test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// recorder keeps the events of a module in the order they happened.
type recorder struct {
	mu     sync.Mutex
	events []token.Event
	fail   error
}

func (r *recorder) Record(_ context.Context, e token.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) kinds() []token.EventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]token.EventKind, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Kind)
	}
	return out
}

func (r *recorder) last() token.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[len(r.events)-1]
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

// world is a module over a real database, with a clock and a recorder.
type world struct {
	db     *data.DB
	raw    *sql.DB
	module *token.Module
	svc    *token.Service
	clock  *clock
	log    *recorder
	engine string
}

// eachDatabase runs fn on SQLite and, when ARANDU_TEST_POSTGRES_DSN is set, on
// PostgreSQL, each on a database of its own.
func eachDatabase(t *testing.T, configure func(*token.Config), fn func(t *testing.T, w *world)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, newSQLite(t, configure)) })
	t.Run("postgres", func(t *testing.T) {
		if os.Getenv(postgresDSN) == "" {
			t.Skip("no server: set " + postgresDSN)
		}
		fn(t, newPostgres(t, configure))
	})
}

func newSQLite(t *testing.T, configure func(*token.Config)) *world {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token.sqlite")
	raw, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+sqliteOptions)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = raw.Close() })
	return install(t, raw, data.DialectSQLite, string(hedatabase.DialectSQLite), path, configure, "sqlite")
}

func newPostgres(t *testing.T, configure func(*token.Config)) *world {
	t.Helper()
	dsn := os.Getenv(postgresDSN)
	ctx := context.Background()
	suffix := make([]byte, 8)
	_, _ = rand.Read(suffix)
	schema := "token_" + hex.EncodeToString(suffix)

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
	raw, err := sql.Open(pgxconnector.PostgresConnector{}.DriverName(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(16)
	t.Cleanup(func() { _ = raw.Close() })
	return install(t, raw, data.DialectPostgres, "pgsql", schema, configure, "postgres")
}

func install(t *testing.T, raw *sql.DB, dialect data.Dialect, driver, name string, configure func(*token.Config), engine string) *world {
	t.Helper()
	w := &world{raw: raw, clock: newClock(), log: &recorder{}, engine: engine}
	cfg := token.Config{AccessPrefix: "alpra_", RefreshPrefix: "alprr_", Clock: w.clock.Now, Events: w.log}
	if configure != nil {
		configure(&cfg)
	}
	w.db = data.Wrap(raw, dialect)
	module, err := token.New(cfg, w.db)
	if err != nil {
		t.Fatal(err)
	}
	w.module, w.svc = module, module.Service()

	conn := hedatabase.ForMigrations(hedatabase.NewConnection(raw, name, "", map[string]any{"driver": driver, "name": "token-test"}))
	for _, m := range module.Migrations() {
		if err := m.Up(context.Background(), conn); err != nil {
			t.Fatalf("applying %s: %v", m.GetName(), err)
		}
	}
	return w
}

// dump is every row of both tables as one string, to look for what must not be
// there.
func (w *world) dump(t *testing.T) string {
	t.Helper()
	var out string
	for _, table := range []string{"token_credentials", "token_devices"} {
		rows, err := w.raw.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range values {
				out += cols[i] + "=" + asText(v) + "\n"
			}
		}
		_ = rows.Close()
	}
	return out
}

func asText(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(x)
	}
}

// count answers the number of rows a query selects.
func (w *world) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := w.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// issue signs a device in and fails the test when it cannot.
func (w *world) issue(t *testing.T, user, workspace, device string) token.Pair {
	t.Helper()
	pair, err := w.svc.Issue(context.Background(), user, workspace, token.Device{ID: device, Name: "Aparelho " + device, Platform: "android"})
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// resolves reports whether an access token is accepted.
func (w *world) resolves(t *testing.T, access string) (token.Principal, bool) {
	t.Helper()
	p, ok, err := w.svc.Resolve(context.Background(), token.DigestOf(access))
	if err != nil {
		t.Fatal(err)
	}
	return p, ok
}
