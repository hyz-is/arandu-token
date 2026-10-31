package unit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	token "github.com/hyz-is/arandu-token"
)

func TestAZeroSecretPrintsLikeAFullOne(t *testing.T) {
	var zero token.Secret
	if !zero.IsZero() || zero.Reveal() != "" {
		t.Fatal("the zero secret is not empty")
	}
	if got, want := fmt.Sprint(zero), "[redacted]"; got != want {
		t.Fatalf("zero prints %q, want %q: a log line must not tell a missing token from a present one", got, want)
	}
}

func TestEveryVerbAndEncodingOfAPairHidesTheTokens(t *testing.T) {
	pair := freshPair(t)
	access, refresh := pair.Access.Reveal(), pair.Refresh.Reveal()
	if access == "" || refresh == "" {
		t.Fatal("the helper did not make a pair")
	}

	var outputs []string
	for _, v := range []any{pair, &pair, pair.Access, &pair.Refresh, pair.Reveal()} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%e", "%f", "%t", "%c", "%U", "%p", "%T"} {
			outputs = append(outputs, fmt.Sprintf(verb, v))
		}
		outputs = append(outputs, fmt.Sprint(v), fmt.Sprintln(v), fmt.Sprintf("%10.3v|%-20s|%+q", v, v, v))
		for _, h := range []slog.Handler{
			slog.NewTextHandler(&bytes.Buffer{}, nil), slog.NewJSONHandler(&bytes.Buffer{}, nil),
		} {
			var buf bytes.Buffer
			switch h.(type) {
			case *slog.TextHandler:
				h = slog.NewTextHandler(&buf, nil)
			default:
				h = slog.NewJSONHandler(&buf, nil)
			}
			slog.New(h).Info("pair", "v", v, slog.Group("g", slog.Any("inner", v)))
			outputs = append(outputs, buf.String())
		}
	}
	for _, v := range []any{pair, pair.Access, pair.Refresh, map[string]any{"a": pair.Access}, []token.Secret{pair.Access}, struct{ S token.Secret }{pair.Access}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(b))
	}
	// A struct of the application's that holds a secret, printed with a verb that
	// does not fit it, which makes fmt dump the fields itself.
	type session struct {
		User   string
		Secret token.Secret
		Pair   token.Pair
	}
	for _, verb := range []string{"%p", "%d", "%v", "%+v", "%#v", "%x", "%s"} {
		outputs = append(outputs, fmt.Sprintf(verb, session{"ana", pair.Access, pair}), fmt.Sprintf(verb, &session{"ana", pair.Access, pair}))
	}

	for _, out := range outputs {
		if strings.Contains(out, access) || strings.Contains(out, refresh) ||
			strings.Contains(out, strings.TrimPrefix(access, "alpra_")) || strings.Contains(out, strings.TrimPrefix(refresh, "alprr_")) {
			t.Fatalf("a token reached an output: %.160q", out)
		}
	}
}

func TestRevealIsTheDoorAndBuildsTheBodyOfASignIn(t *testing.T) {
	pair := freshPair(t)
	body, err := json.Marshal(pair.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		TokenType        string    `json:"token_type"`
		AccessToken      string    `json:"access_token"`
		RefreshToken     string    `json:"refresh_token"`
		ExpiresIn        int       `json:"expires_in"`
		AccessExpiresAt  time.Time `json:"access_expires_at"`
		RefreshExpiresAt time.Time `json:"refresh_expires_at"`
		WorkspaceID      string    `json:"workspace_id"`
		DeviceID         string    `json:"device_id"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.TokenType != "Bearer" || got.AccessToken != pair.Access.Reveal() || got.RefreshToken != pair.Refresh.Reveal() ||
		got.ExpiresIn != 900 || got.WorkspaceID != "ws-1" || got.DeviceID != "phone-1" ||
		!got.AccessExpiresAt.Equal(pair.AccessExpires) || !got.RefreshExpiresAt.Equal(pair.RefreshExpires) {
		t.Fatalf("body = %s", body)
	}
	if b, _ := json.Marshal(token.Revealed{}); string(b) != "null" {
		t.Fatalf("the body of the zero Revealed = %s", b)
	}
}

func TestThePairLogsItsExpiryAndBindingAndNoToken(t *testing.T) {
	pair := freshPair(t)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("issued", "pair", pair)
	for _, want := range []string{"access_expires=", "workspace_id=ws-1", "device_id=phone-1"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the log line lacks %s: %s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), pair.Access.Reveal()) {
		t.Fatal("the log line carries the access token")
	}
}

func TestADigestIsTheFrameworksAndIsHex(t *testing.T) {
	d := token.DigestOf("alpra_abc")
	if len(d.String()) != 64 || strings.Trim(d.String(), "0123456789abcdef") != "" {
		t.Fatalf("digest = %q", d.String())
	}
}
