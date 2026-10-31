package feature_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/security"
	hedatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"
	"github.com/arandu-io/hesape/database/migrations"

	token "github.com/hyz-is/arandu-token"
)

func TestNewRefusesAWiringThatCannotWork(t *testing.T) {
	handle := data.Wrap(nil, data.DialectSQLite)
	for name, cfg := range map[string]token.Config{
		"same prefixes":                     {AccessPrefix: "t_", RefreshPrefix: "t_"},
		"one prefix starting another":       {AccessPrefix: "tk", RefreshPrefix: "tk_r"},
		"a prefix with a space":             {AccessPrefix: "my app_"},
		"a prefix that is too long":         {AccessPrefix: strings.Repeat("a", 17)},
		"a prefix starting with a digit":    {RefreshPrefix: "1r_"},
		"a negative access lifetime":        {AccessTTL: -time.Minute},
		"an access token for a week":        {AccessTTL: 7 * 24 * time.Hour},
		"a refresh shorter than the access": {AccessTTL: time.Hour, RefreshTTL: time.Minute},
		"a refresh for ten years":           {RefreshTTL: 3650 * 24 * time.Hour},
		"a negative retention":              {Retention: -1},
		"a grace of an hour":                {ReuseGrace: time.Hour},
		"a clean with three fields":         {CleanSpec: "0 3 *"},
	} {
		if _, err := token.New(cfg, handle); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := token.New(token.Config{}, nil); err == nil {
		t.Error("a nil database was accepted")
	}
	if _, err := token.New(token.Config{}, handle); err != nil {
		t.Errorf("the zero configuration was refused: %v", err)
	}
	if _, err := token.NewService(token.Config{}, nil); err == nil {
		t.Error("NewService accepted a nil database")
	}
}

func TestTheModuleDeclaresWhatItOwns(t *testing.T) {
	m, err := token.New(token.Config{}, data.Wrap(nil, data.DialectSQLite))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name() != "token" {
		t.Fatalf("Name = %q", m.Name())
	}
	// It has no endpoint: registering it adds no route.
	router := fhttp.NewRouter()
	m.Routes(router)
	if m.Service() == nil {
		t.Fatal("no service")
	}
	all := m.Migrations()
	if len(all) != 1 || all[0].GetName() != "20261031_0001_create_token_tables" {
		t.Fatalf("migrations = %v", all)
	}
	if _, ok := all[0].(migrations.ReversibleMigration); !ok {
		t.Fatal("the migration has no Down")
	}
	var _ foundation.Module = m
}

func TestTheScheduleDeclaresTheClean(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		tasks := w.module.Schedule()
		if len(tasks) != 1 {
			t.Fatalf("tasks = %d, want the clean", len(tasks))
		}
		task := tasks[0]
		if task.ID != "token.credentials.clean" || task.Spec != "17 3 * * *" || task.Scope != foundation.Global ||
			!task.Singleton || task.Action != token.TokenClean || task.Timeout <= 0 {
			t.Fatalf("task = %+v", task)
		}

		// Running it deletes what expired.
		w.issue(t, "ana", "ws-1", "phone-1")
		w.clock.Advance(400 * 24 * time.Hour)
		if err := task.Run(ctx, nilGrant()); err != nil {
			t.Fatal(err)
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials`); n != 0 {
			t.Fatalf("%d credentials left after the scheduled clean", n)
		}
	})
}

func TestTheCleanCanBeMovedOrTurnedOff(t *testing.T) {
	handle := data.Wrap(nil, data.DialectSQLite)
	moved, _ := token.New(token.Config{CleanSpec: "0 5 * * 0"}, handle)
	if got := moved.Schedule(); len(got) != 1 || got[0].Spec != "0 5 * * 0" {
		t.Fatalf("moved = %+v", got)
	}
	off, _ := token.New(token.Config{CleanSpec: token.CleanDisabled}, handle)
	if got := off.Schedule(); len(got) != 0 {
		t.Fatalf("disabled = %+v", got)
	}
}

func TestHealthSaysWhetherTheTablesAreThere(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		if err := w.module.Health(ctx); err != nil {
			t.Fatalf("Health after migrating: %v", err)
		}
	})

	path := t.TempDir() + "/empty.sqlite"
	raw, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	m, err := token.New(token.Config{}, data.Wrap(raw, data.DialectSQLite))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err == nil || !strings.Contains(err.Error(), "aru migrate") {
		t.Fatalf("Health before migrating: %v, want a pointer to aru migrate", err)
	}
}

func TestTheMigrationGoesUpDownAndUp(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		conn := hedatabase.ForMigrations(hedatabase.NewConnection(w.raw, "again", "", map[string]any{"driver": driverOf(w), "name": "token-test"}))
		m := w.module.Migrations()[0].(migrations.ReversibleMigration)
		if err := m.Down(ctx, conn); err != nil {
			t.Fatalf("Down: %v", err)
		}
		if err := w.module.Health(ctx); err == nil {
			t.Fatal("the tables are still there after Down")
		}
		if err := m.Up(ctx, conn); err != nil {
			t.Fatalf("Up again: %v", err)
		}
		if err := w.module.Health(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func driverOf(w *world) string {
	if w.engine == "postgres" {
		return "pgsql"
	}
	return string(hedatabase.DialectSQLite)
}

func TestTheTablesCarryThePackagesName(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		// A host application has its own devices and tokens tables, and these
		// must be able to sit beside them.
		for _, table := range []string{"devices", "tokens"} {
			if _, err := w.raw.Exec(`CREATE TABLE ` + table + ` (id VARCHAR(10) PRIMARY KEY)`); err != nil {
				t.Fatalf("the application's own %s table collides: %v", table, err)
			}
		}
	})
}

// nilGrant is the zero Grant the scheduler hands a global task, which can pass
// no check and so cannot reach anything on its own.
func nilGrant() security.Grant { return security.Grant{} }
