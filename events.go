package token

import (
	"context"
	"time"
)

// EventKind says what happened to a credential.
type EventKind string

// The kinds of event. The strings are stable: an application stores them in
// its activity log and reads them back.
const (
	// EventIssued is a pair given to a device at sign-in.
	EventIssued EventKind = "token.issued"
	// EventRefreshed is a refresh token exchanged for a new pair.
	EventRefreshed EventKind = "token.refreshed"
	// EventReuseDetected is a refresh token presented after it had been
	// exchanged. The family of that device was revoked in the same act.
	EventReuseDetected EventKind = "token.reuse_detected"
	// EventRevoked is a session ended: by the device signing out, by its owner
	// removing it, by every device being signed out, or by a new sign-in
	// replacing it. Reason says which.
	EventRevoked EventKind = "token.revoked"
	// EventSwitched is a session moved to another workspace. The old pair was
	// revoked and a new one issued.
	EventSwitched EventKind = "token.switched"
)

// The reasons a session ends, in Event.Reason.
const (
	// ReasonSignedOut is the device ending its own session with Revoke.
	ReasonSignedOut = "signed_out"
	// ReasonDeviceRemoved is RevokeDevice.
	ReasonDeviceRemoved = "device_removed"
	// ReasonAllDevices is RevokeAllForUser.
	ReasonAllDevices = "all_devices"
	// ReasonReplaced is a new sign-in on a device that already had a session.
	ReasonReplaced = "replaced"
	// ReasonReuse is the family revoked because a refresh token was reused.
	ReasonReuse = "reuse"
	// ReasonSwitched is the old pair of a workspace switch.
	ReasonSwitched = "switched"

	// reasonRotated marks a refresh token that was exchanged. It is how a reuse
	// is told from a plain revocation, and it is stored, not reported: the
	// exchange is an EventRefreshed.
	reasonRotated = "rotated"
)

// Event is what an application records about a credential.
//
// It names people, devices and workspaces and never a token or a digest, so it
// can be written to the activity log, to a file or to the screen of whoever
// operates the application.
type Event struct {
	// Kind says what happened.
	Kind EventKind
	// UserID is the account the session belongs to.
	UserID string
	// WorkspaceID is the workspace the session was bound to, as a candidate.
	WorkspaceID string
	// PreviousWorkspaceID is the workspace a switch left, and empty otherwise.
	PreviousWorkspaceID string
	// DeviceID is the device the session belongs to.
	DeviceID string
	// FamilyID names the session: every pair a device receives from one sign-in
	// shares it.
	FamilyID string
	// Reason says why a session ended, for EventRevoked and EventReuseDetected.
	Reason string
	// IP is the address the act came from, when the context carried one.
	IP string
	// At is when it happened, in UTC.
	At time.Time
}

// Recorder receives the events of Config.Events.
//
// Record runs inside the transaction of the act it records, on a context that
// carries it: a recorder that writes with the application's database handle,
// such as an activity log, joins the transaction and rolls back with it. An
// error from Record fails the act, because an act the log does not know of
// should not have happened. A recorder that must not fail the act swallows its
// own error and returns nil.
//
// The module never decides what the application does with an event. The README
// shows the function that writes it to arandu-activitylog.
type Recorder interface {
	Record(ctx context.Context, event Event) error
}

// RecorderFunc adapts a function to a Recorder.
type RecorderFunc func(ctx context.Context, event Event) error

// Record calls f.
func (f RecorderFunc) Record(ctx context.Context, event Event) error { return f(ctx, event) }
