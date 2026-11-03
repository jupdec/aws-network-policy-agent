package controllers

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// PodIdentityReconciler keeps each local pod on the identity its labels give. It acts on the
// node-scoped pod informer when a pod's labels change, and when a pod becomes network-ready
// (it may have started under an isolated identity because its labels were unreadable, or
// still be filtered by programs from before an agent restart that the startup sweep did not
// reach). It moves the pod, then reconciles the policies around it so the old identity's
// bindings are pruned and the new one's are complete.
type PodIdentityReconciler struct {
	client      client.Reader
	enforcer    PodEnforcer
	startupGate <-chan struct{}
}

// NewPodIdentityReconciler constructs a PodIdentityReconciler reading pods from reader.
func NewPodIdentityReconciler(reader client.Reader, enforcer PodEnforcer, startupGate <-chan struct{}) *PodIdentityReconciler {
	return &PodIdentityReconciler{client: reader, enforcer: enforcer, startupGate: startupGate}
}

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *PodIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := waitForStartupGate(ctx, r.startupGate); err != nil {
		return ctrl.Result{}, err
	}
	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			// CNI DEL releases the pod.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.syncPod(ctx, pod)
}

func (r *PodIdentityReconciler) syncPod(ctx context.Context, pod *corev1.Pod) error {
	if pod.Spec.HostNetwork || pod.DeletionTimestamp != nil || pod.Status.PodIP == "" {
		// Nothing attached (host network), about to be released (CNI DEL), or not started
		// yet (CNI ADD will attach it).
		return nil
	}
	podName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	res := podidentity.FromPod(pod)
	if attached, ok := r.enforcer.ebpfClient().AttachedPodIdentifier(podName); ok && attached == res.Identity {
		return nil
	}
	log().Infof("Moving pod %s to podIdentifier %s", podName, res.Identity)
	if err := r.enforcer.Move(ctx, podName, res, moveOptions{}); err != nil {
		return err
	}
	return errors.Join(
		r.enforcer.Policy.reconcileNamespace(ctx, pod.Namespace),
		r.enforcer.ClusterPolicy.reconcileListing(ctx, podName),
	)
}

// podIdentityEvents passes the pod events that can change which identity a pod belongs on.
var podIdentityEvents = predicate.Funcs{
	CreateFunc: func(event.CreateEvent) bool { return true },
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldPod, okOld := e.ObjectOld.(*corev1.Pod)
		newPod, okNew := e.ObjectNew.(*corev1.Pod)
		if !okOld || !okNew {
			return false
		}
		return !maps.Equal(oldPod.Labels, newPod.Labels) || oldPod.Status.PodIP != newPod.Status.PodIP
	},
	DeleteFunc:  func(event.DeleteEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// SetupWithManager watches pods through the manager's cache, which config scopes to this
// node's pods (podidentity.PodCacheByObject).
func (r *PodIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("podidentity").
		For(&corev1.Pod{}, builder.WithPredicates(podIdentityEvents)).
		Complete(r)
}

// sweepRetryBackoff bounds the delay between startup sweep attempts.
var sweepRetryBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}

// IdentitySweep is the startup pass that puts every network-ready local pod on its label
// identity before the reconcilers run. An agent restart loses the record of which pod uses
// which program, and an upgrade from name-prefix identifiers has every pod on a program
// keyed by its name; both leave the pods filtered by programs that survived in bpffs. The
// sweep moves each pod onto its label identity in place (see PodEnforcer.Move), with its
// maps programmed first, so there is no unfiltered or default-state window. Once every pod
// is swept, programs no pod uses any more -- the name-prefix ones after an upgrade -- are
// deleted.
//
// It closes Gate after its first pass, whether or not every pod was swept, and keeps
// retrying the failures in the background.
type IdentitySweep struct {
	// Pods lists this node's pods (the node-scoped cache).
	Pods client.Reader
	// WaitForCacheSync waits until the manager's informers are synced.
	WaitForCacheSync func(ctx context.Context) bool
	// Resolver is told when the pod cache can be read.
	Resolver *podidentity.APIResolver
	Enforcer PodEnforcer
	// Gate is closed after the first pass.
	Gate chan struct{}

	closeGate sync.Once
}

// Start implements manager.Runnable.
func (s *IdentitySweep) Start(ctx context.Context) error {
	defer s.closeGate.Do(func() { close(s.Gate) })
	if !s.WaitForCacheSync(ctx) {
		return fmt.Errorf("pod identity sweep: caches did not sync")
	}
	if s.Resolver != nil {
		s.Resolver.MarkCacheReady()
	}
	for attempt := 0; ; attempt++ {
		failed, err := s.sweepOnce(ctx)
		if attempt == 0 {
			s.closeGate.Do(func() { close(s.Gate) })
		}
		if err == nil && failed == 0 {
			return nil
		}
		log().Errorf("Pod identity sweep left %d pods unmoved (attempt %d): %v", failed, attempt+1, err)
		delay := sweepRetryBackoff[min(attempt, len(sweepRetryBackoff)-1)]
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every node sweeps its own pods.
func (s *IdentitySweep) NeedLeaderElection() bool {
	return false
}

// sweepOnce moves every network-ready local pod and, if all of them moved, releases the
// programs no pod uses any more. It returns the number of pods it failed to move.
func (s *IdentitySweep) sweepOnce(ctx context.Context) (int, error) {
	podList := &corev1.PodList{}
	if err := s.Pods.List(ctx, podList); err != nil {
		return 0, fmt.Errorf("list local pods: %w", err)
	}
	keep := map[string]bool{}
	failed := 0
	var errs error
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Spec.HostNetwork || pod.Status.PodIP == "" ||
			pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		res := podidentity.FromPod(pod)
		keep[res.Identity] = true
		podName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
		if err := s.Enforcer.Move(ctx, podName, res, moveOptions{bindClusterPoliciesByMembership: true}); err != nil {
			failed++
			errs = errors.Join(errs, err)
		}
	}
	if failed > 0 {
		// A pod that did not move may still be filtered by a program that looks unused, so
		// nothing is released until every pod has moved.
		return failed, errs
	}
	if released := s.Enforcer.ebpfClient().ReleaseUnusedPodIdentifiers(keep); len(released) > 0 {
		log().Infof("Pod identity sweep released %d podIdentifiers no pod uses: %v", len(released), released)
	}
	return 0, nil
}
