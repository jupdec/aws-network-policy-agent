package controllers

import (
	"context"

	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"k8s.io/apimachinery/pkg/types"
)

// The reconciler tests predate label identities and assert on the binding and cleanup logic
// with identifiers derived from pod names. They keep doing so through this resolver, which
// exists only in the test binary: production resolves through podidentity.APIResolver and
// never derives an identity from a name.
func init() {
	defaultIdentityResolver = func() podidentity.Resolver { return nameBasedTestResolver{} }
}

type nameBasedTestResolver struct{}

func (nameBasedTestResolver) Resolve(_ context.Context, pod types.NamespacedName) (podidentity.Result, error) {
	return podidentity.Result{Identity: utils.GetPodIdentifier(pod.Name, pod.Namespace), Labels: map[string]string{}}, nil
}

func (r nameBasedTestResolver) ResolveCached(ctx context.Context, pod types.NamespacedName) (podidentity.Result, error) {
	return r.Resolve(ctx, pod)
}

// labelTestResolver resolves pods from a fixed set of labels, as the API server would.
// Pods it does not know are deleted.
type labelTestResolver map[types.NamespacedName]map[string]string

func (r labelTestResolver) Resolve(_ context.Context, pod types.NamespacedName) (podidentity.Result, error) {
	podLabels, ok := r[pod]
	if !ok {
		return podidentity.Result{}, podidentity.ErrPodNotFound
	}
	return podidentity.Result{Identity: utils.PodIdentity(podLabels, pod.Namespace), Labels: podLabels}, nil
}

func (r labelTestResolver) ResolveCached(ctx context.Context, pod types.NamespacedName) (podidentity.Result, error) {
	return r.Resolve(ctx, pod)
}

// nameIdentity is the identityFunc of nameBasedTestResolver.
func nameIdentity(pod types.NamespacedName) (string, bool) {
	return utils.GetPodIdentifier(pod.Name, pod.Namespace), true
}
