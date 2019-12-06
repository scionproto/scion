package trustdbsqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/trustdbtest"
)

var _ trustdbtest.TestableTrustDB = (*TestTrustDB)(nil)

type TestTrustDB struct {
	*Backend
}

func (b *TestTrustDB) Prepare(t *testing.T, _ context.Context) {
	b.Backend = newDatabase(t)
}

func TestTrustDBSuite(t *testing.T) {
	trustdbtest.TestTrustDB(t, &TestTrustDB{})
}

func newDatabase(t *testing.T) *Backend {
	db, err := New(":memory:")
	require.NoError(t, err)
	return db
}
