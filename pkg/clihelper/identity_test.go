package clihelper

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	"github.com/stretchr/testify/assert"
)

func TestDescribeIdentity(t *testing.T) {
	identities := map[string]podidentity.IdentityInfo{
		"aaa@prod": {Labels: map[string]string{"tier": "data", "app": "db"}, Pods: []string{"prod/db-0", "prod/db-1"}},
		"iso@prod": {Pods: []string{"prod/db-evil"}},
	}
	assert.Equal(t, "Labels : {app=db, tier=data}\nPods : prod/db-0, prod/db-1\n", describeIdentity(identities, "aaa@prod"))
	assert.Equal(t, "Labels : (unavailable: isolated identity)\nPods : prod/db-evil\n", describeIdentity(identities, "iso@prod"))
	assert.Equal(t, "Labels : (no local pod uses this identity)\n", describeIdentity(identities, "old@prod"))
	assert.Equal(t, "", describeIdentity(nil, "aaa@prod"))
}
