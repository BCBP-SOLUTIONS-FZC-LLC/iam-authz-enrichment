package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

func TestWrapConnErr_AvailabilitySQLStateMapsToUnavailable(t *testing.T) {
	for _, code := range []string{"08006", "53300", "57P01", "58030"} {
		t.Run(code, func(t *testing.T) {
			got := wrapConnErr(&pgconn.PgError{Code: code})
			assert.ErrorIs(t, got, domain.ErrUnavailable)
		})
	}
}

func TestWrapConnErr_ConstraintPgErrorPassesThroughUnchanged(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505"}
	assert.Same(t, pgErr, wrapConnErr(pgErr))
}

func TestWrapConnErr_DomainSentinelsPassThroughUnchanged(t *testing.T) {
	assert.ErrorIs(t, wrapConnErr(domain.ErrUnavailable), domain.ErrUnavailable)
	assert.ErrorIs(t, wrapConnErr(domain.ErrNotFound), domain.ErrNotFound)
}

func TestWrapConnErr_PgxNoRowsPassesThroughUnchanged(t *testing.T) {
	// pgx.ErrNoRows sentinel — tested by message string rather than importing
	// pgx directly, keeping all pgx-ecosystem imports out of production paths.
	noRows := errors.New("no rows in result set")
	got := wrapConnErr(noRows)
	assert.Same(t, noRows, got)
}

func TestWrapConnErr_UnrecognizedGenericErrorPassesThroughUnchanged(t *testing.T) {
	businessErr := errors.New("dial tcp: connection refused")
	got := wrapConnErr(businessErr)
	assert.Same(t, businessErr, got)
}

func TestWrapConnErr_ClosedPoolMapsToUnavailable(t *testing.T) {
	// puddle.ErrClosedPool = errors.New("closed pool") — matched by
	// isClosedPool's string sentinel, so we never import puddle directly.
	assert.ErrorIs(t, wrapConnErr(errors.New("closed pool")), domain.ErrUnavailable)
}

func TestWrapConnErr_ContextErrorsPassThroughUnchanged(t *testing.T) {
	assert.ErrorIs(t, wrapConnErr(context.Canceled), context.Canceled)
	assert.ErrorIs(t, wrapConnErr(context.DeadlineExceeded), context.DeadlineExceeded)
}

func TestWrapConnErr_NilPassesThrough(t *testing.T) {
	assert.NoError(t, wrapConnErr(nil))
}

func TestWrapConnErr_NonPgErrorIsNotOperatorClass(t *testing.T) {
	assert.False(t, isOperatorOrSystemErrorSQLState(errors.New("not a pg error")))
}

func TestIsClosedPool_NilReturnsFalse(t *testing.T) {
	// wrapConnErr returns nil before ever calling isClosedPool(nil), so
	// the nil path of isClosedPool itself requires a direct call here.
	assert.False(t, isClosedPool(nil))
}
