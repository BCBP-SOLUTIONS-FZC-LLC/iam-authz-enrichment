package postgres

import (
	"errors"
	"strings"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/pgcommon"
)

// wrapConnErr maps connectivity/resource Postgres failures onto
// domain.ErrUnavailable using platform-pgcommon's SQLSTATE helpers — the
// same classification iam-user-profile / iam-org-membership apply inside
// RunInTx / withPool. SQL-protocol errors that are not class 08/53/57/58
// pass through unchanged so a future repository layer can distinguish
// integrity violations from an outage. Unrecognized plain Go errors also
// pass through (never remapped to unavailable).
func wrapConnErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if pgcommon.IsConnectionException(err) || pgcommon.IsInsufficientResources(err) || isOperatorOrSystemErrorSQLState(err) || isClosedPool(err) {
		return domain.ErrUnavailable
	}
	return err
}

// isOperatorOrSystemErrorSQLState reports SQLSTATE class 57/58.
// pgcommon v1.3.0 covers 08/53 but not these two; classify via the
// pgconn Error() text so callers never import pgconn directly.
func isOperatorOrSystemErrorSQLState(err error) bool {
	if !pgcommon.IsPgError(err) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLSTATE 57") || strings.Contains(msg, "SQLSTATE 58")
}

// isClosedPool reports whether err is a puddle "closed pool" error —
// returned when a query is attempted on a pgxpool that has already been
// closed (typically during graceful shutdown). Checked by error-message
// text rather than importing "github.com/jackc/puddle/v2" directly, which
// would bypass the platform-pgcommon-only database-routing invariant.
// puddle.ErrClosedPool = errors.New("closed pool") — the message is a
// stable sentinel inside the pgx/puddle library, not a user-facing string.
func isClosedPool(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "closed pool")
}
