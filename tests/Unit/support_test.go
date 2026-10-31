package unit_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/arandu-io/framework/data"
	hedatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"

	token "github.com/hyz-is/arandu-token"
)

// freshPair issues a real pair on a throwaway SQLite database.
func freshPair(t *testing.T) token.Pair {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unit.sqlite")
	raw, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+"?_txlock=immediate&_pragma=busy_timeout(20000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	m, err := token.New(token.Config{AccessPrefix: "alpra_", RefreshPrefix: "alprr_"}, data.Wrap(raw, data.DialectSQLite))
	if err != nil {
		t.Fatal(err)
	}
	conn := hedatabase.ForMigrations(hedatabase.NewConnection(raw, path, "", map[string]any{"driver": string(hedatabase.DialectSQLite), "name": "unit"}))
	for _, migration := range m.Migrations() {
		if err := migration.Up(ctx, conn); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := m.Service().Issue(ctx, "ana", "ws-1", token.Device{ID: "phone-1", Name: "Pixel", Platform: "android"})
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
