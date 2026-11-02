package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPodIdentity_IgnoresPodName(t *testing.T) {
	// The Robosec repro: db-0 and db-evil collide under GetPodIdentifier...
	assert.Equal(t, GetPodIdentifier("db-0", "prod"), GetPodIdentifier("db-evil", "prod"))

	// ...but differ under PodIdentity because their labels differ.
	db := PodIdentity(map[string]string{"app": "db"}, "prod")
	evil := PodIdentity(map[string]string{"app": "evil"}, "prod")
	assert.NotEqual(t, db, evil)
}

func TestPodIdentity_SameLabelsShareIdentity(t *testing.T) {
	a := PodIdentity(map[string]string{"app": "api", "pod-template-hash": "7d9f"}, "prod")
	b := PodIdentity(map[string]string{"pod-template-hash": "7d9f", "app": "api"}, "prod")
	assert.Equal(t, a, b, "map iteration order must not affect the identity")
}

func TestPodIdentity_NamespaceScoped(t *testing.T) {
	labels := map[string]string{"app": "db"}
	assert.NotEqual(t, PodIdentity(labels, "prod"), PodIdentity(labels, "dev"))
}

func TestPodIdentity_NoLabelSplicing(t *testing.T) {
	// {a: "b\nc=d"} cannot exist (newline is illegal in a value), but adjacent-key
	// splicing must still not collide for legal inputs.
	one := PodIdentity(map[string]string{"a": "b", "c": "d"}, "ns")
	two := PodIdentity(map[string]string{"a": "bc", "": "d"}, "ns")
	assert.NotEqual(t, one, two)
}

func TestPodIdentity_RelabelChangesIdentity(t *testing.T) {
	before := PodIdentity(map[string]string{"app": "db"}, "prod")
	after := PodIdentity(map[string]string{"app": "maintenance"}, "prod")
	assert.NotEqual(t, before, after)
}

func TestPodIdentity_PinPathSafe(t *testing.T) {
	id := PodIdentity(map[string]string{"app": "db"}, "prod")
	assert.Len(t, strings.Split(id, "@")[0], 32)
	assert.NotContains(t, id, "_", "an '_' would break GetPodIdentifierFromBPFPinPath")

	// Round-trips through the pin path helpers.
	pinPath := GetBPFPinPathFromPodIdentifier(id, "ingress")
	gotID, gotDir := GetPodIdentifierFromBPFPinPath(pinPath)
	assert.Equal(t, id, gotID)
	assert.Equal(t, "ingress", gotDir)
}

func TestPodIdentity_Golden(t *testing.T) {
	// Pinned so an accidental recipe change fails loudly; bump podIdentityVersion instead.
	tests := []struct {
		labels map[string]string
		want   string
	}{
		{map[string]string{"app": "db"}, "9d2497a7c2997f1c1ed51bb81886a647@prod"},
		{map[string]string{"app": "evil"}, "3dd2f78e07b4f1003f40cd6675246d12@prod"},
		{nil, "2d27fbdf4e8ca207afbfa388ca9172fb@prod"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, PodIdentity(tt.labels, "prod"))
	}
}
