package usecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// One test per row of the §7 failure-handling matrix, per §12.
func TestDecideDependencyOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		state usecase.DependencyState
		want  usecase.DependencyOutcome
	}{
		{
			name:  "everything healthy",
			state: usecase.DependencyState{ValkeyReachable: true, SiblingReachable: true},
			want:  usecase.OutcomeNormal,
		},
		{
			name: "row 1: Valkey down, sibling healthy -> bypass, not fail closed",
			state: usecase.DependencyState{
				ValkeyReachable: false, SiblingReachable: true, StaleEntryAvailable: false,
			},
			want: usecase.OutcomeNormal,
		},
		{
			name: "row 2: sibling down, Valkey healthy, stale entry available -> serve stale",
			state: usecase.DependencyState{
				ValkeyReachable: true, SiblingReachable: false, StaleEntryAvailable: true,
			},
			want: usecase.OutcomeServeStale,
		},
		{
			name: "row 2 degenerate: sibling down, Valkey healthy, but nothing ever cached -> fail closed",
			state: usecase.DependencyState{
				ValkeyReachable: true, SiblingReachable: false, StaleEntryAvailable: false,
			},
			want: usecase.OutcomeFailClosed,
		},
		{
			name: "row 3: both down -> fail closed",
			state: usecase.DependencyState{
				ValkeyReachable: false, SiblingReachable: false, StaleEntryAvailable: false,
			},
			want: usecase.OutcomeFailClosed,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, usecase.DecideDependencyOutcome(c.state))
		})
	}
}
