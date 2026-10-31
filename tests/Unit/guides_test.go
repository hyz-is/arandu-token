package unit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheGuidesTeachExplicitCompositionInOneFile keeps the installation surface
// as explicit as the constructor. A package is composed in bootstrap/app.go;
// another bootstrap file would be another place a reader has to search to learn
// what the application contains.
func TestTheGuidesTeachExplicitCompositionInOneFile(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	bootstrapFile := regexp.MustCompile(`bootstrap/[A-Za-z0-9_.-]+\.go`)
	for _, guide := range []string{"README.md", ".agents/skills/token-package/SKILL.md"} {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(guide)))
		if err != nil {
			t.Fatalf("reading %s: %v", guide, err)
		}
		text := string(body)
		for _, required := range []string{"bootstrap/app.go", "token.New(", "k.Register", "aru migrate"} {
			if !strings.Contains(text, required) {
				t.Errorf("%s no longer teaches %q", guide, required)
			}
		}
		for _, referenced := range bootstrapFile.FindAllString(text, -1) {
			if referenced != "bootstrap/app.go" {
				t.Errorf("%s introduces a second composition file %s", guide, referenced)
			}
		}
	}
}

// TestEverySkillIsNamedForItsDirectory holds the rule the skills README states:
// a skill whose name differs from its directory is not loaded.
func TestEverySkillIsNamedForItsDirectory(t *testing.T) {
	t.Parallel()

	skills, err := filepath.Glob(filepath.Join(packageRoot(t), ".agents", "skills", "*", "SKILL.md"))
	if err != nil || len(skills) == 0 {
		t.Fatalf("no skill found: %v", err)
	}
	for _, path := range skills {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile(`(?m)^name: (\S+)$`).FindStringSubmatch(string(body))
		directory := filepath.Base(filepath.Dir(path))
		if match == nil || match[1] != directory {
			t.Errorf("%s declares the name %v, want %q", path, match, directory)
		}
	}
}

// TestNoGuideTeachesTheShapeThisPackageDoesNotHave keeps the vocabulary of the
// template it was started from out of the documents: this package has no
// generated model, no policy of its own and no routes.
func TestNoGuideTeachesTheShapeThisPackageDoesNotHave(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	retired := []string{"aru model:build", "Tokens(db)", "TokenQuery", "vendor:publish", "token-policy", "TokenPolicy", "TokenService"}
	for _, guide := range []string{
		"README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
		".agents/skills/README.md", ".agents/skills/token-package/SKILL.md",
		".agents/skills/token-module/SKILL.md", ".agents/skills/token-secrecy/SKILL.md",
	} {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(guide)))
		if err != nil {
			t.Fatalf("reading %s: %v", guide, err)
		}
		for _, stale := range retired {
			if strings.Contains(string(body), stale) {
				t.Errorf("%s still teaches %q", guide, stale)
			}
		}
	}
}
