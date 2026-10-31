package token

import "github.com/arandu-io/framework/security"

// The actions this package names. Constants rather than strings at the call
// site: a typo in an action name would silently authorize nothing, or worse,
// everything.
//
// There is one, and it is not offered to people. A person's access to their own
// devices is the application's to grant, through arandu-permission and its own
// policies, since this package knows a user by an identifier and nothing more.
const (
	// TokenClean is the scheduled deletion of expired and revoked credentials.
	// No Subject is ever given it: the scheduler runs the clean and the clean
	// reaches only this package's tables.
	TokenClean security.Action = "token.clean"
)
