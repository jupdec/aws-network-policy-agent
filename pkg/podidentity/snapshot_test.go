package podidentity

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

func TestSnapshot_RecordForgetAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities.json")
	s := NewSnapshot(path)
	db0 := types.NamespacedName{Namespace: "prod", Name: "db-0"}
	db1 := types.NamespacedName{Namespace: "prod", Name: "db-1"}
	evil := types.NamespacedName{Namespace: "prod", Name: "db-evil"}
	s.Record(db0, "aaa@prod", map[string]string{"app": "db"})
	s.Record(db1, "aaa@prod", map[string]string{"app": "db"})
	s.Record(evil, "iso@prod", nil)

	require.NoError(t, s.flush())
	got, err := ReadSnapshot(path)
	require.NoError(t, err)
	assert.Equal(t, map[string]IdentityInfo{
		"aaa@prod": {Labels: map[string]string{"app": "db"}, Pods: []string{"prod/db-0", "prod/db-1"}},
		"iso@prod": {Labels: nil, Pods: []string{"prod/db-evil"}},
	}, got)

	// A move and a delete.
	s.Record(db1, "bbb@prod", map[string]string{"app": "maintenance"})
	s.Forget(evil)
	require.NoError(t, s.flush())
	got, err = ReadSnapshot(path)
	require.NoError(t, err)
	assert.Equal(t, map[string]IdentityInfo{
		"aaa@prod": {Labels: map[string]string{"app": "db"}, Pods: []string{"prod/db-0"}},
		"bbb@prod": {Labels: map[string]string{"app": "maintenance"}, Pods: []string{"prod/db-1"}},
	}, got)
}

func TestSnapshot_NilIsSafe(t *testing.T) {
	var s *Snapshot
	s.Record(types.NamespacedName{Name: "x"}, "id", nil)
	s.Forget(types.NamespacedName{Name: "x"})
}

func TestSnapshot_FlushSkipsWhenUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities.json")
	s := NewSnapshot(path)
	require.NoError(t, s.flush())
	_, err := ReadSnapshot(path)
	assert.Error(t, err, "nothing recorded, nothing written")
}
