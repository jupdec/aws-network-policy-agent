package controllers

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Pod identity in the reconcilers.
//
// Every pod is enforced under utils.PodIdentity(labels, namespace), so pods share eBPF
// programs and maps only when their labels are identical. Two identities are in play for a
// local pod:
//
//   - the attached identity: the one its TC filters point at, recorded by the eBPF client.
//     It is what the pod is enforced under right now, and it survives the pod object being
//     deleted, so cleanup and CNI DEL use it.
//   - the label identity: computed from the labels the API server reports now.
//
// They differ only while a move is pending (a relabel, labels that became readable after
// the pod started under an isolated identity, or the first start after upgrading from
// name-prefix identifiers). The pod identity controller moves the pod; until then the pod
// is not bound under either identity by a reconcile, so no other pod's rules are written to
// maps it shares.
//
// No path falls back to a name-derived identifier. A pod whose identity cannot be
// determined is skipped (cleanup) or requeued (programming).

// defaultIdentityResolver is the resolver a reconciler uses until SetIdentityResolver is
// called. It resolves nothing. Tests replace it.
var defaultIdentityResolver = func() podidentity.Resolver { return podidentity.Unconfigured{} }

// errIdentityMovePending is returned for a pod whose labels no longer match the identity it
// is attached to. The pod identity controller moves it and requeues the namespace.
var errIdentityMovePending = errors.New("pod identity move pending")

// knownPodIdentity returns the identity a local pod is enforced under, for cleanup and
// tracking: the attached one, else the label one from the cache. It never reads the API
// server: those paths mostly visit deleted pods, and a pod with no attached identity has
// nothing on this node to clean up.
func knownPodIdentity(ctx context.Context, resolver podidentity.Resolver, ebpfClient ebpf.BpfClient,
	pod types.NamespacedName) (string, bool) {
	if ebpfClient != nil {
		if podIdentifier, ok := ebpfClient.AttachedPodIdentifier(pod); ok {
			return podIdentifier, true
		}
	}
	res, err := resolver.ResolveCached(ctx, pod)
	if err != nil {
		return "", false
	}
	return res.Identity, true
}

// targetPodIdentity returns the identity to program a local pod a policy selects under,
// with the pod's labels. The API server is consulted on a cache miss: the pod is expected
// to exist.
//
// errIdentityMovePending is returned if the pod is attached under a different identity
// than its labels give, and podidentity.ErrPodNotFound if the pod is gone.
func targetPodIdentity(ctx context.Context, resolver podidentity.Resolver, ebpfClient ebpf.BpfClient,
	pod types.NamespacedName) (string, podidentity.Result, error) {
	res, err := resolver.Resolve(ctx, pod)
	if err != nil {
		return "", res, err
	}
	if ebpfClient != nil {
		if attached, ok := ebpfClient.AttachedPodIdentifier(pod); ok && attached != res.Identity {
			return "", res, fmt.Errorf("%w: pod %s is attached to %s, labels give %s",
				errIdentityMovePending, pod, attached, res.Identity)
		}
	}
	return res.Identity, res, nil
}

// selectorMatches reports whether a PolicyEndpoint's pod selector selects podLabels. A nil
// selector matches nothing: the selector is how a pod is checked, so without one the pod
// cannot be confirmed.
func selectorMatches(selector *metav1.LabelSelector, podLabels map[string]string) (bool, error) {
	if selector == nil {
		return false, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}
	return sel.Matches(labels.Set(podLabels)), nil
}

// identityFunc resolves a pod to its identity, reporting false when it cannot.
type identityFunc func(types.NamespacedName) (string, bool)

func ctrlRequest(namespace, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}
}
