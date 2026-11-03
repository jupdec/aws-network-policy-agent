// Package podidentity resolves the label-based enforcement identity of pods on this node.
//
// The identity is utils.PodIdentity(labels, namespace). Labels always come from the API
// server -- the node-scoped pod informer, or a live GET -- never from the CNI request, and
// a pod whose labels cannot be read is never given an identity derived from its name.
package podidentity

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// liveGetTimeout bounds a live GET so a slow API server cannot hold up a CNI ADD.
const liveGetTimeout = 5 * time.Second

var (
	// ErrPodNotFound means the API server has no such pod: it was deleted.
	ErrPodNotFound = errors.New("pod not found")
	// ErrUnavailable means the pod's labels could not be read. Callers must apply the mode
	// default and must not fall back to a name-derived identifier.
	ErrUnavailable = errors.New("pod labels unavailable")
)

// Result is a resolved pod.
type Result struct {
	// Identity is utils.PodIdentity(Labels, namespace).
	Identity string
	// Labels are the pod's labels as read from the API server. Never nil.
	Labels map[string]string
	// PodIP is the pod's primary IP, empty until the pod is network-ready.
	PodIP string
	// HostNetwork pods have no eBPF programs of their own.
	HostNetwork bool
}

// Resolver resolves pods to their identity.
type Resolver interface {
	// Resolve reads the pod from the node-local cache and, on a miss or while the cache is
	// not ready, from the API server.
	Resolve(ctx context.Context, pod types.NamespacedName) (Result, error)
	// ResolveCached reads the pod from the node-local cache only. It returns ErrUnavailable
	// while the cache is not ready. For cleanup paths, where the pod is usually deleted and
	// a live GET per pod would only confirm that.
	ResolveCached(ctx context.Context, pod types.NamespacedName) (Result, error)
}

// APIResolver is the production Resolver.
type APIResolver struct {
	// cache is the manager's informer-backed reader, scoped to this node's pods. Nil when
	// the node name is unknown, in which case only live reads are used.
	cache client.Reader
	// live reads straight from the API server. It works before the manager starts.
	live client.Reader
	// cacheReady is set once the pod informer has synced. Reading the cache earlier
	// returns ErrCacheNotStarted or a partial view.
	cacheReady atomic.Bool
}

var _ Resolver = (*APIResolver)(nil)

// NewAPIResolver returns a resolver that reads from cache, once MarkCacheReady is called,
// and falls back to live. cache may be nil.
func NewAPIResolver(cache, live client.Reader) *APIResolver {
	return &APIResolver{cache: cache, live: live}
}

// MarkCacheReady is called once the pod informer has synced.
func (r *APIResolver) MarkCacheReady() {
	if r.cache != nil {
		r.cacheReady.Store(true)
	}
}

// CacheReady reports whether the node-local pod cache is in use.
func (r *APIResolver) CacheReady() bool {
	return r.cacheReady.Load()
}

func (r *APIResolver) Resolve(ctx context.Context, nn types.NamespacedName) (Result, error) {
	if r.cacheReady.Load() {
		res, err := r.ResolveCached(ctx, nn)
		if err == nil {
			return res, nil
		}
		// A miss can be informer lag for a pod that has just been created, so it is not
		// conclusive: ask the API server.
		if !errors.Is(err, ErrPodNotFound) {
			log().Debugf("Pod cache read failed for %s, falling back to a live read: %v", nn, err)
		}
	}
	if r.live == nil {
		return Result{}, fmt.Errorf("%w: no API reader for pod %s", ErrUnavailable, nn)
	}
	getCtx, cancel := context.WithTimeout(ctx, liveGetTimeout)
	defer cancel()
	pod := &corev1.Pod{}
	if err := r.live.Get(getCtx, nn, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return Result{}, fmt.Errorf("%w: %s", ErrPodNotFound, nn)
		}
		return Result{}, fmt.Errorf("%w: get pod %s: %v", ErrUnavailable, nn, err)
	}
	return FromPod(pod), nil
}

func (r *APIResolver) ResolveCached(ctx context.Context, nn types.NamespacedName) (Result, error) {
	if !r.cacheReady.Load() {
		return Result{}, fmt.Errorf("%w: pod cache not ready", ErrUnavailable)
	}
	pod := &corev1.Pod{}
	if err := r.cache.Get(ctx, nn, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return Result{}, fmt.Errorf("%w: %s", ErrPodNotFound, nn)
		}
		return Result{}, fmt.Errorf("%w: cached get pod %s: %v", ErrUnavailable, nn, err)
	}
	return FromPod(pod), nil
}

// FromPod computes the Result for a pod object read from the API server.
func FromPod(pod *corev1.Pod) Result {
	podLabels := pod.Labels
	if podLabels == nil {
		podLabels = map[string]string{}
	}
	return Result{
		Identity:    utils.PodIdentity(podLabels, pod.Namespace),
		Labels:      podLabels,
		PodIP:       pod.Status.PodIP,
		HostNetwork: pod.Spec.HostNetwork,
	}
}

// Unconfigured is the Resolver used until one is set. It resolves nothing, so every pod
// gets the mode default rather than an identity derived from its name.
type Unconfigured struct{}

var _ Resolver = Unconfigured{}

func (Unconfigured) Resolve(context.Context, types.NamespacedName) (Result, error) {
	return Result{}, fmt.Errorf("%w: no pod identity resolver configured", ErrUnavailable)
}

func (Unconfigured) ResolveCached(context.Context, types.NamespacedName) (Result, error) {
	return Result{}, fmt.Errorf("%w: no pod identity resolver configured", ErrUnavailable)
}
