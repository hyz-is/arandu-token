package feature_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/arandu-io/framework/security"
	"net/http"

	token "github.com/hyz-is/arandu-token"
)

// capture sends everything the standard loggers write to a buffer for the
// length of the test.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, flags, out := slog.Default(), log.Flags(), log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&buf)
	t.Cleanup(func() { slog.SetDefault(previous); log.SetOutput(out); log.SetFlags(flags) })
	return &buf
}

func TestNoTokenIsEverStoredLoggedPrintedOrEncoded(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		logged := capture(t)

		// A whole life: sign in, use, rotate, switch, reuse, revoke.
		var secrets []string
		note := func(p token.Pair) token.Pair {
			secrets = append(secrets, p.Access.Reveal(), p.Refresh.Reveal())
			return p
		}
		first := note(w.issue(t, "ana", "ws-1", "phone-1"))
		app := memberships{"ana": {"ws-1", "ws-2"}}
		handler := w.svc.RequireToken(app.subjectFor)(http.HandlerFunc(answer))
		request(handler, "Bearer "+first.Access.Reveal(), "/")
		second, err := w.svc.Refresh(ctx, first.Refresh.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		note(second)
		third, err := w.svc.Switch(ctx, second.Access.Reveal(), "ws-2")
		if err != nil {
			t.Fatal(err)
		}
		note(third)

		// Everything that can fail, failing with the real tokens as its input.
		var failures []error
		_, err = w.svc.Refresh(ctx, first.Refresh.Reveal())
		failures = append(failures, err) // a reuse
		_, err = w.svc.Refresh(ctx, second.Refresh.Reveal())
		failures = append(failures, err)
		_, err = w.svc.Switch(ctx, first.Access.Reveal(), "ws-1")
		failures = append(failures, err)
		_, err = w.svc.Refresh(ctx, third.Access.Reveal())
		failures = append(failures, err)
		failures = append(failures, w.svc.Revoke(ctx, third.Refresh.Reveal()))
		for _, f := range failures {
			if f == nil {
				continue
			}
			for _, s := range secrets {
				if strings.Contains(f.Error(), s) || strings.Contains(fmt.Sprintf("%+v %#v", f, f), s) {
					t.Fatalf("an error carries a token: %v", f)
				}
			}
		}
		// A wrapped recorder error is where an event could drag a value along.
		w.log.fail = errors.New("down")
		_, err = w.svc.Issue(ctx, "ana", "ws-1", token.Device{ID: "phone-2"})
		w.log.fail = nil
		if err == nil {
			t.Fatal("expected the recorder failure")
		}

		// Every way of printing and encoding what holds a token.
		pair := note(w.issue(t, "ana", "ws-1", "phone-3"))
		revealed := pair.Reveal()
		var shown []string
		for _, v := range []any{pair, &pair, pair.Access, pair.Refresh, revealed, &revealed, w.log.last(), w.log.events} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%T", "%p"} {
				shown = append(shown, fmt.Sprintf(verb, v))
			}
			shown = append(shown, fmt.Sprint(v), fmt.Sprintln(v))
		}
		for _, v := range []any{pair, pair.Access, pair.Refresh, revealed, w.log.last()} {
			slog.Info("signed in", "value", v)
			slog.Info("signed in", slog.Any("value", v), slog.Group("g", "v", v))
			log.Printf("signed in: %v %+v %s", v, v, v)
		}
		// json of the Secret and the Pair never has the tokens; json of Revealed
		// does, because that is the body that hands them over.
		for _, v := range []any{pair, pair.Access, pair.Refresh, map[string]any{"pair": pair}} {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			shown = append(shown, string(b))
			var out bytes.Buffer
			enc := json.NewEncoder(&out)
			enc.SetIndent("", " ")
			_ = enc.Encode(v)
			shown = append(shown, out.String())
		}
		text, err := pair.Access.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		shown = append(shown, string(text))
		shown = append(shown, logged.String())

		for _, out := range shown {
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Fatalf("a token reached an output: %.200q", out)
				}
			}
		}
		// And Reveal is the one door.
		body, err := json.Marshal(revealed)
		if err != nil || !strings.Contains(string(body), pair.Access.Reveal()) || !strings.Contains(string(body), pair.Refresh.Reveal()) {
			t.Fatalf("Reveal does not build the body that hands the tokens over: %s, %v", body, err)
		}
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		if decoded["token_type"] != "Bearer" || decoded["expires_in"] != float64(900) || decoded["device_id"] != "phone-3" {
			t.Fatalf("body = %v", decoded)
		}

		// The store holds digests, and every token's digest is in it.
		stored := w.dump(t)
		for _, s := range secrets {
			if strings.Contains(stored, s) || strings.Contains(stored, strings.TrimPrefix(strings.TrimPrefix(s, "alpra_"), "alprr_")) {
				t.Fatalf("a token, or the random part of one, is in the tables")
			}
		}
		for _, p := range []token.Pair{first, second, third, pair} {
			for _, s := range []string{p.Access.Reveal(), p.Refresh.Reveal()} {
				if !strings.Contains(stored, token.DigestOf(s).String()) {
					t.Fatalf("the digest of a token is not in the tables")
				}
			}
		}
		_ = security.Subject{}
	})
}
