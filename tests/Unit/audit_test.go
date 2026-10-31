package unit_test

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// What this package proves about itself, before anybody installs it.
//
// `aru doctor` audits the application it is run inside. It walks that project's
// own tree, reads the one arandu.mod.toml at its root, and never loads a
// dependency. So nothing an installed package does is audited by the
// application that installed it, and whatever this one must prove about itself
// it proves here or nowhere.
//
// These tests read the package's own Go files as syntax and hold the properties
// a credential store lives by:
//
//  1. what arandu.mod.toml declares is what the code does;
//  2. a token leaves the package through one door, Secret.Reveal, called in one
//     place;
//  3. nothing here logs, prints or formats on its own, so no token can be
//     written by a line somebody forgot;
//  4. no statement is handed a token: the store receives digests;
//  5. no address is read from a header the client writes.
//
// What they do not reach is worth as much as what they do. They read syntax: a
// call hidden behind an interface and anything reached by reflection are
// invisible to them. A green run means no such thing was found written down, not
// that none exists. The behaviour is held by the feature tests, which drive a
// whole life of tokens through a real database and look for them in every
// output.

// a tag is left out of the audit whatever it is called: what the compiler never
// builds is not part of what the package does, and reporting it as such would
// be reporting a capability nobody can reach.
func buildable(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, comment := range group.List {
			expression, err := constraint.Parse(comment.Text)
			if err != nil {
				continue
			}
			// No tag set, which is what the gates run with.
			if !expression.Eval(func(string) bool { return false }) {
				return false
			}
		}
	}
	return true
}

// linked reports whether an application that installs this package compiles
// this file into its binary.
//
// A command is not linked. `go get` of a library never pulls in the main
// package beside it, and `go build` of the application never reaches it, so
// what a command does is not a capability anybody who installs this agreed to.
// Auditing one would make the manifest declare a capability that no running
// application has -- which is the same defect as declaring one nothing uses,
// pointed the other way.
//
// The package carries no command today, and the rule is here rather than in the
// commit that adds one: a capability audit that grows a hole the first time
// somebody needs it is an audit whose answer depends on who ran it.
//
// Every rule in this file reads what the installer links, and this is where
// that is decided once.
func linked(file *ast.File) bool { return file.Name.Name != "main" }

// auditedFiles is every Go file an application that installs this package
// compiles into its binary.
func auditedFiles(t *testing.T) []parsedGoFile {
	t.Helper()

	out := []parsedGoFile{}
	for _, source := range productionGoFiles(t, packageRoot(t)) {
		if buildable(source.file) && linked(source.file) {
			out = append(out, source)
		}
	}
	// An audit with nothing to read passes, and a test that passes by finding
	// nothing is the failure mode of every rule below.
	if len(out) == 0 {
		t.Fatal("no buildable Go file was found, so everything below would pass by having nothing to read")
	}
	return out
}

// selectorName is the trailing name of a selector, or the name of an
// identifier.
func selectorName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.SelectorExpr:
		return expression.Sel.Name
	case *ast.Ident:
		return expression.Name
	}
	return ""
}

// calledName is the trailing name of whatever a call names, so a call can be
// recognised without resolving what it is called on.
func calledName(call *ast.CallExpr) string {
	return selectorName(call.Fun)
}

// firstCallTo is where a body first calls something by this name.
func firstCallTo(body *ast.BlockStmt, name string) token.Pos {
	found := token.NoPos
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || calledName(call) != name {
			return true
		}
		if found == token.NoPos || call.Pos() < found {
			found = call.Pos()
		}
		return true
	})
	return found
}

// TestAnAccessTokenLeavesThroughOneDoor holds that the only call of Reveal in
// the package is the one that builds the body of the answer, in secret.go.
//
// Reveal is how a Secret becomes a string. Anywhere else it is called, the
// string can be put in an error, a statement or a log line.
func TestAnAccessTokenLeavesThroughOneDoor(t *testing.T) {
	t.Parallel()

	revealed := 0
	for _, source := range auditedFiles(t) {
		ast.Inspect(source.file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || calledName(call) != "Reveal" {
				return true
			}
			revealed++
			if source.path != "secret.go" {
				t.Errorf("%s calls Reveal: a token becomes a string only in secret.go", source.path)
			}
			return true
		})
	}
	if revealed == 0 {
		t.Fatal("no call of Reveal was found, so this test proved nothing")
	}
}

// TestNothingInThePackageLogsPrintsOrReadsAHeaderOfTheClient holds that the
// production code writes to no logger and no stream, and takes the address of a
// request from RemoteAddr alone.
func TestNothingInThePackageLogsPrintsOrReadsAHeaderOfTheClient(t *testing.T) {
	t.Parallel()

	forbidden := map[string]bool{
		"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true,
		"fmt.Fprint": true, "fmt.Fprintf": true, "fmt.Fprintln": true,
		"log.Print": true, "log.Printf": true, "log.Println": true,
		"log.Fatal": true, "log.Fatalf": true, "log.Panic": true, "log.Panicf": true,
		"slog.Debug": true, "slog.Info": true, "slog.Warn": true, "slog.Error": true,
		"slog.Log": true, "println": true, "print": true,
	}
	for _, source := range auditedFiles(t) {
		standard := standardImports(source.file)
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				if name := qualifiedName(node, standard); forbidden[name] {
					t.Errorf("%s calls %s: this package writes to no log and no stream, so no token can be written by it", source.path, name)
				}
			case *ast.BasicLit:
				if strings.EqualFold(strings.Trim(node.Value, `"`), "X-Forwarded-For") ||
					strings.EqualFold(strings.Trim(node.Value, `"`), "X-Real-IP") ||
					strings.EqualFold(strings.Trim(node.Value, `"`), "Forwarded") {
					t.Errorf("%s reads %s, which the client writes: the address comes from RemoteAddr", source.path, node.Value)
				}
			}
			return true
		})
	}
}

// TestNoStatementIsHandedAToken holds that no argument of a database call is a
// variable named for a token. What the store receives is a digest, and the
// variables that hold one are named for that.
func TestNoStatementIsHandedAToken(t *testing.T) {
	t.Parallel()

	statements := map[string]bool{"exec": true, "ExecContext": true, "QueryContext": true, "QueryRowContext": true, "byDigest": true}
	tokens := map[string]bool{"token": true, "access": true, "refresh": true, "raw": true, "bearer": true}
	checked := 0
	for _, source := range auditedFiles(t) {
		ast.Inspect(source.file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !statements[calledName(call)] {
				return true
			}
			checked++
			for _, argument := range call.Args {
				ast.Inspect(argument, func(inner ast.Node) bool {
					if identifier, ok := inner.(*ast.Ident); ok && tokens[identifier.Name] {
						t.Errorf("%s hands %q to %s: the store keeps digests, never tokens", source.path, identifier.Name, calledName(call))
					}
					return true
				})
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no database call was found, so this test proved nothing")
	}
}

// TestThePackageIsComposedByHand holds that nothing in it is a service
// provider, a container or a global registry.
func TestThePackageIsComposedByHand(t *testing.T) {
	t.Parallel()

	for _, source := range auditedFiles(t) {
		for _, imported := range source.file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if strings.Contains(path, "/container") {
				t.Errorf("%s imports the container surface %s", source.path, path)
			}
		}
		for _, declaration := range source.file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				name := declaration.Name.Name
				if declaration.Recv == nil && (name == "init" || strings.Contains(name, "Provider") || name == "Register") {
					t.Errorf("%s declares %s, which makes composition implicit", source.path, name)
				}
			case *ast.GenDecl:
				if declaration.Tok != token.VAR {
					continue
				}
				for _, spec := range declaration.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range value.Names {
						if name.Name == "_" || strings.HasPrefix(name.Name, "Err") || strings.HasPrefix(name.Name, "err") ||
							strings.HasSuffix(name.Name, "Pattern") || name.Name == "identifier" {
							continue
						}
						t.Errorf("%s declares the package variable %s: a mutable global is a hidden registry", source.path, name.Name)
					}
				}
			}
		}
	}
}

// the same four names.
type capabilities struct {
	network    bool
	filesystem bool
	exec       bool
	migrations bool
}

// TestTheDeclaredCapabilitiesAreWhatTheCodeDoes is the audit the installer
// cannot run. `aru doctor` compares an application's manifest against the
// application's code; the manifest of a package it installed is never opened,
// so this comparison exists here or nowhere.
//
// Both directions fail. Using more than was declared is the one that costs
// somebody something, and the doctor calls it an error too. Declaring more than
// is used is milder -- a warning, there -- and it fails here because `go test`
// has one outcome and because asking for what is not needed is how a
// declaration stops being worth reading.
func TestTheDeclaredCapabilitiesAreWhatTheCodeDoes(t *testing.T) {
	t.Parallel()

	declared := declaredCapabilities(t)
	used := usedCapabilities(auditedFiles(t))

	for _, capability := range []struct {
		name        string
		declared    bool
		used        bool
		consequence string
	}{
		{"network", declared.network, used.network,
			"the code makes calls that leave the process, and whoever installs it agreed to a package that does not"},
		{"filesystem", declared.filesystem, used.filesystem,
			"the code reads or writes files outside the database, which nothing in its API shows"},
		{"exec", declared.exec, used.exec,
			"the code runs another program, which is the widest capability there is"},
		{"migrations", declared.migrations, used.migrations,
			"the code owns tables, and an installer who did not expect that will not know to migrate before deploying"},
	} {
		switch {
		case capability.used && !capability.declared:
			t.Errorf("arandu.mod.toml declares %s = false and the code uses it: %s. Declare it, or remove what needs it",
				capability.name, capability.consequence)
		case capability.declared && !capability.used:
			t.Errorf("arandu.mod.toml declares %s = true and nothing uses it: set %s = false, or the declaration stops being worth reading",
				capability.name, capability.name)
		}
	}
}

// declaredCapabilities reads the [permissions] block.
//
// By hand, because the alternative is a third dependency in a module that is
// compiled into other people's builds, and four booleans do not earn one.
func declaredCapabilities(t *testing.T) capabilities {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(packageRoot(t), "arandu.mod.toml"))
	if err != nil {
		t.Fatalf("reading arandu.mod.toml: %v", err)
	}

	var declared capabilities
	seen := map[string]bool{}
	inside := false

	for _, line := range strings.Split(string(body), "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inside = line == "[permissions]"
			continue
		}
		if !inside {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		seen[key] = true
		switch key {
		case "network":
			declared.network = value == "true"
		case "filesystem":
			declared.filesystem = value == "true"
		case "exec":
			declared.exec = value == "true"
		case "migrations":
			declared.migrations = value == "true"
		}
	}

	for _, required := range []string{"network", "filesystem", "exec", "migrations"} {
		if !seen[required] {
			t.Errorf("arandu.mod.toml leaves %s undeclared under [permissions]; silence reads as false to whoever installs this, and a capability nobody declared is one nobody agreed to",
				required)
		}
	}
	return declared
}

// usedCapabilities is what the code actually does, by syntax.
//
// It reads calls rather than imports, for the reason the manifest gives: this
// package imports net/http for a method constant and a request type, and an
// import says nothing about whether anything leaves the process.
func usedCapabilities(files []parsedGoFile) capabilities {
	var used capabilities

	for _, source := range files {
		if strings.Contains(source.path, "migrations/") {
			used.migrations = true
		}
		for _, imported := range source.file.Imports {
			switch strings.Trim(imported.Path.Value, `"`) {
			case "os/exec":
				used.exec = true
			case "net/smtp", "net/rpc":
				used.network = true
			case "io/ioutil":
				used.filesystem = true
			}
		}

		standard := standardImports(source.file)
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				switch name := qualifiedName(node, standard); {
				case name == "http.Get", name == "http.Post", name == "http.Head",
					name == "http.PostForm", name == "http.NewRequest",
					name == "http.NewRequestWithContext",
					name == "net.Dial", name == "net.DialTimeout",
					strings.HasSuffix(name, ".Do"):
					used.network = true

				case name == "os.Open", name == "os.OpenFile", name == "os.Create",
					name == "os.ReadFile", name == "os.WriteFile", name == "os.Remove",
					name == "os.RemoveAll", name == "os.Mkdir", name == "os.MkdirAll",
					name == "os.Rename", name == "os.ReadDir",
					name == "filepath.Walk", name == "filepath.WalkDir":
					used.filesystem = true

				case name == "exec.Command", name == "exec.CommandContext", name == "syscall.Exec":
					used.exec = true
				}
			case *ast.FuncDecl:
				if node.Recv != nil && node.Name.Name == "Migrations" {
					used.migrations = true
				}
			}
			return true
		})
	}
	return used
}

// standardImports maps the local name of every standard library import to the
// package's own name, so an aliased import is recognised by what it is.
//
// Only the standard library, because the names matched above are its names. A
// third-party package whose last element is "http" is not net/http, and reading
// it as one reports a router helper as an outbound call.
func standardImports(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
			continue
		}

		name := path
		if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
			name = path[slash+1:]
		}
		local := name
		if imported.Name != nil {
			local = imported.Name.Name
		}
		out[local] = name
	}
	return out
}

// qualifiedName is a call as "package.Function" where the receiver is an
// imported package, and ".Method" where it is a value.
func qualifiedName(call *ast.CallExpr, standard map[string]string) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		if identifier, ok := call.Fun.(*ast.Ident); ok {
			return identifier.Name
		}
		return ""
	}
	owner, ok := selector.X.(*ast.Ident)
	if !ok {
		return "." + selector.Sel.Name
	}
	if name, imported := standard[owner.Name]; imported {
		return name + "." + selector.Sel.Name
	}
	return owner.Name + "." + selector.Sel.Name
}

// packageRoot is the directory of the module.
func packageRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("finding package root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

type parsedGoFile struct {
	path string
	file *ast.File
}

// productionGoFiles parses every Go file of the module that is not a test or
// generated view, comments kept because a build constraint is one.
func productionGoFiles(t *testing.T, root string) []parsedGoFile {
	t.Helper()

	files := []parsedGoFile{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata" || entry.Name() == "tests") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") || strings.HasSuffix(entry.Name(), ".kyse.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, parsedGoFile{path: filepath.ToSlash(relative), file: file})
		return nil
	})
	if err != nil {
		t.Fatalf("reading production Go files: %v", err)
	}
	return files
}
