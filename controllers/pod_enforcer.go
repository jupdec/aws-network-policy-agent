package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// fastPathLockWait bounds how long a pod start waits for a reconcile to release the binding
// maps. Past it, the pod starts in the mode default and the reconcile applies its rules, as
// it would without the fast path.
const fastPathLockWait = 2 * time.Second

// PodEnforcer applies policy to one local pod: when it starts (CNI ADD), when it is deleted
// (CNI DEL), and when its identity changes. The reconcilers apply policy per
// (Cluster)PolicyEndpoint; this applies it per pod, through the same binding maps.
type PodEnforcer struct {
	Policy        *PolicyEndpointsReconciler
	ClusterPolicy *ClusterPolicyEndpointsReconciler
}

func (e PodEnforcer) ebpfClient() ebpf.BpfClient {
	return e.Policy.GeteBPFClient()
}

// EnforceNewPod attaches a starting pod and programs its maps if this is the first pod of
// its identity on the node. The identity comes from the pod's labels; if they cannot be
// read, the pod gets an isolated identity of its own in the mode default, and the pod
// identity controller moves it once they can.
//
// mode is the network policy mode from the CNI request.
func (e PodEnforcer) EnforceNewPod(ctx context.Context, pod types.NamespacedName, numInterfaces int, mode string) error {
	podIdentifier := ""
	var podLabels map[string]string
	res, err := e.Policy.resolver().Resolve(ctx, pod)
	switch {
	case err == nil && res.HostNetwork:
		// No veth to attach to. CNI does not call the agent for these, but be safe.
		return nil
	case err == nil:
		podIdentifier, podLabels = res.Identity, res.Labels
	default:
		podIdentifier = utils.IsolatedPodIdentity(pod.Name, pod.Namespace)
		log().Warnf("Labels of pod %s are unavailable (%v); enforcing it under its own identity %s in the mode default until they are",
			pod, err, podIdentifier)
	}

	// podConfirmedLive=true: a CNI ADD is proof the pod exists.
	isFirstPodInPodIdentifier, err := e.ebpfClient().AttacheBPFProbes(pod, podIdentifier, numInterfaces, true)
	if err != nil {
		log().Errorf("Attaching eBPF probe failed for pod: %s namespace: %s, error: %v", pod.Name, pod.Namespace, err)
		return err
	}
	if attached, ok := e.ebpfClient().AttachedPodIdentifier(pod); ok && attached != podIdentifier {
		// A repeated CNI ADD for a pod that is already attached keeps it where it is; the
		// pod identity controller moves it. Don't bind or program the other identity.
		log().Infof("Pod %s is already attached to podIdentifier %s; leaving the move to %s to the pod identity controller",
			pod, attached, podIdentifier)
		return nil
	}

	e.Policy.identitySnapshot.Record(pod, podIdentifier, podLabels)
	if podLabels != nil {
		e.Policy.bindLocalPodBySelector(ctx, pod, podIdentifier, podLabels)
	}
	return e.programIdentity(ctx, podIdentifier, pod.Namespace, isFirstPodInPodIdentifier, mode)
}

// programIdentity programs the maps of an identifier that a pod has just joined. If this
// node already had programs for it, the pod shares maps the reconcilers keep up to date and
// nothing is written. Otherwise the maps are new: they get the rules of the policies bound
// to the identifier, or the mode default if none are.
func (e PodEnforcer) programIdentity(ctx context.Context, podIdentifier, namespace string, isNew bool, mode string) error {
	var err error
	podState := ebpf.DEFAULT_ALLOW
	if utils.IsStrictMode(mode) {
		podState = ebpf.DEFAULT_DENY
	}
	clusterPolicyState := ebpf.DEFAULT_ALLOW

	// We attempt to program eBPF firewall map entries for this pod, if the local agent is aware of the policies
	// configured against it. For example, if this is a new replica of an existing pod/deployment then the local
	// node agent will have the policy information available to it. If not, we will leave the pod in default allow
	// or default deny state based on NP mode until the Network Policy controller reconciles existing policies
	// against this pod.
	policiesAvailableInLocalCache := e.Policy.ArePoliciesAvailableInLocalCache(podIdentifier)
	clusterPolicyAvailableInLocalCache := e.ClusterPolicy.ArePoliciesAvailableInLocalCache(podIdentifier)

	if (policiesAvailableInLocalCache || clusterPolicyAvailableInLocalCache) && isNew {
		log().Info("Active policies present against this pod and this is a new Pod to the local node, configuring firewall rules....")

		if policiesAvailableInLocalCache {
			ingressRules, egressRules, _ := e.Policy.DeriveFireWallRulesPerPodIdentifier(podIdentifier, namespace)
			if err = e.ebpfClient().UpdateEbpfMaps(podIdentifier, ingressRules, egressRules); err != nil {
				log().Errorf("Network Policy map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return err
			}
			podState = ebpf.POLICIES_APPLIED
		}

		if clusterPolicyAvailableInLocalCache {
			clusterIngressRules, clusterEgressRules, _ :=
				e.ClusterPolicy.DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx, podIdentifier)
			if err = e.ClusterPolicy.GeteBPFClient().UpdateClusterPolicyEbpfMaps(podIdentifier, clusterIngressRules, clusterEgressRules); err != nil {
				log().Errorf("Cluster Policy map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return err
			}
			clusterPolicyState = ebpf.POLICIES_APPLIED
		}

		if err = e.ebpfClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.POD_STATE_MAP_KEY, podState, true, true); err != nil {
			log().Errorf("Pod state map update failed for podIdentifier: %s, while updating network policy state, error: %v", podIdentifier, err)
			return err
		}
		if err = e.ClusterPolicy.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, clusterPolicyState, true, true); err != nil {
			log().Errorf("Pod state map update failed for podIdentifier: %s updating cluster network policy state, error: %v", podIdentifier, err)
			return err
		}
		return nil
	}

	if policiesAvailableInLocalCache || clusterPolicyAvailableInLocalCache {
		log().Info("Pod shares the eBPF firewall maps with other local pods. No Map update required..")
		return nil
	}

	// No active policies against this identifier: default allow or default deny.
	log().Infof("Updating pod_state map to default allow/default deny for podIdentifier: %s for network policy state, value: %d", podIdentifier, podState)
	if err = e.ebpfClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.POD_STATE_MAP_KEY, podState, true, true); err != nil {
		log().Errorf("Pod state map update failed for podIdentifier: %s, while updating network policy state, error: %v", podIdentifier, err)
		return err
	}
	log().Infof("Updating pod_state map to default allow for podIdentifier: %s, for cluster network policy state, value: %d", podIdentifier, ebpf.DEFAULT_ALLOW)
	// No concept of default deny for cluster policies. Either we have a rule that allows or denies traffic
	if err = e.ClusterPolicy.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.DEFAULT_ALLOW, true, true); err != nil {
		log().Errorf("Pod state map update failed for podIdentifier: %s while updating cluster network policy state, error: %v", podIdentifier, err)
		return err
	}
	return nil
}

// DeletePod releases a deleted pod's programs. The pod is released from the identifier it
// is attached to; its labels may already be gone.
func (e PodEnforcer) DeletePod(ctx context.Context, pod types.NamespacedName) error {
	podIdentifier, _ := knownPodIdentity(ctx, e.Policy.resolver(), e.ebpfClient(), pod)
	e.Policy.identitySnapshot.Forget(pod)
	return e.ebpfClient().DeleteBPFProbes(pod, podIdentifier)
}

// moveOptions tunes Move.
type moveOptions struct {
	// bindClusterPoliciesByMembership binds the cluster policies whose CPE lists the pod by
	// name and IP. Only for the startup sweep, where the pod's labels are what they were
	// when NPC listed it: after a relabel, a CPE still listing the pod under its old labels
	// would bind the new identity to a policy that no longer selects it.
	bindClusterPoliciesByMembership bool
}

// Move puts a running pod under the identity its labels give: it loads and programs that
// identity's maps, then replaces the pod's TC filters in place, so the pod is never
// unfiltered and never runs in a default state the old rules did not have. It is a no-op if
// the pod is already attached there.
func (e PodEnforcer) Move(ctx context.Context, pod types.NamespacedName, res podidentity.Result, opts moveOptions) error {
	if res.HostNetwork {
		return nil
	}
	if attached, ok := e.ebpfClient().AttachedPodIdentifier(pod); ok && attached == res.Identity {
		return nil
	}
	isNew, err := e.ebpfClient().LoadBPFPrograms(res.Identity)
	if err != nil {
		return fmt.Errorf("load programs for pod %s: %w", pod, err)
	}
	e.Policy.bindLocalPodBySelector(ctx, pod, res.Identity, res.Labels)
	if opts.bindClusterPoliciesByMembership {
		e.ClusterPolicy.bindLocalPodByMembership(ctx, pod, res.Identity, res.PodIP)
	}
	if err := e.programIdentity(ctx, res.Identity, pod.Namespace, isNew, e.ebpfClient().GetNetworkPolicyMode()); err != nil {
		return fmt.Errorf("program maps for pod %s: %w", pod, err)
	}
	if err := e.ebpfClient().RepointBPFProbes(pod, res.Identity, ebpf.INTERFACE_COUNT_UNKNOWN); err != nil {
		return fmt.Errorf("move pod %s to %s: %w", pod, res.Identity, err)
	}
	e.Policy.identitySnapshot.Record(pod, res.Identity, res.Labels)
	return nil
}

// lockWithin acquires mu, giving up after wait.
func lockWithin(mu *sync.Mutex, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for !mu.TryLock() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// bindLocalPodBySelector binds a starting local pod's identity to the NetworkPolicies whose
// PolicyEndpoint selector matches its labels, so the pod gets their rules before NPC lists
// it (#691). It records the binding as a reconcile would (the identity in the parent's
// tracked set, the pod in each slice's selector entry), so a later reconcile that finds the
// pod not listed after all prunes the binding and reprograms the identity.
func (r *PolicyEndpointsReconciler) bindLocalPodBySelector(ctx context.Context, pod types.NamespacedName,
	podIdentifier string, podLabels map[string]string) bool {
	if r.k8sClient == nil {
		return false
	}
	if !lockWithin(&r.bindMu, fastPathLockWait) {
		log().Infof("Skipping policy fast path for pod %s: a reconcile holds the binding maps", pod)
		return false
	}
	defer r.bindMu.Unlock()

	policyEndpointList := &policyk8sawsv1.PolicyEndpointList{}
	if err := r.k8sClient.List(ctx, policyEndpointList, client.InNamespace(pod.Namespace), client.UnsafeDisableDeepCopy); err != nil {
		log().Infof("Skipping policy fast path for pod %s: list PolicyEndpoints: %v", pod, err)
		return false
	}
	slicesByParent := lo.GroupBy(policyEndpointList.Items, func(pe policyk8sawsv1.PolicyEndpoint) string {
		return pe.Spec.PolicyRef.Name
	})

	bound := false
	for parentNP, parentSlices := range slicesByParent {
		selected := lo.ContainsBy(parentSlices, func(pe policyk8sawsv1.PolicyEndpoint) bool {
			matches, err := selectorMatches(pe.Spec.PodSelector, podLabels)
			return err == nil && matches
		})
		if !selected {
			continue
		}
		parentPEList := lo.Map(parentSlices, func(pe policyk8sawsv1.PolicyEndpoint, _ int) string { return pe.Name })
		log().Infof("Fast path: pod %s is selected by NetworkPolicy %s, binding podIdentifier %s", pod, parentNP, podIdentifier)
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap,
			&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentPEList)
		for _, peName := range parentPEList {
			// Keyed like commitPolicyEndpointState, which derives the parent from the slice name.
			addTrackedIdentifier(&r.networkPolicyToPodIdentifierMap,
				utils.GetNetworkPolicyIdentifier(utils.GetParentNPNameFromPEName(peName), pod.Namespace), podIdentifier)
			addSelectedPod(&r.policyEndpointSelectorMap, utils.GetPolicyEndpointIdentifier(peName, pod.Namespace), pod)
		}
		bound = true
	}
	return bound
}

// bindLocalPodByMembership binds a local pod's identity to the cluster policies whose CPE
// lists the pod with its current IP on this node. CPEs carry no selector, so this is the
// cluster-policy counterpart of bindLocalPodBySelector; see moveOptions for when it is safe.
func (r *ClusterPolicyEndpointsReconciler) bindLocalPodByMembership(ctx context.Context, pod types.NamespacedName,
	podIdentifier, podIP string) bool {
	if r.k8sClient == nil || podIP == "" {
		return false
	}
	if !lockWithin(&r.bindMu, fastPathLockWait) {
		log().Infof("Skipping cluster policy fast path for pod %s: a reconcile holds the binding maps", pod)
		return false
	}
	defer r.bindMu.Unlock()

	cpeList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	if err := r.k8sClient.List(ctx, cpeList, client.UnsafeDisableDeepCopy); err != nil {
		log().Infof("Skipping cluster policy fast path for pod %s: list ClusterPolicyEndpoints: %v", pod, err)
		return false
	}
	nodeIP := net.ParseIP(r.nodeIP)
	slicesByParent := lo.GroupBy(cpeList.Items, func(cpe policyk8sawsv1.ClusterPolicyEndpoint) string {
		return cpe.Spec.PolicyRef.Name
	})
	bound := false
	for parentCNP, parentSlices := range slicesByParent {
		listed := lo.ContainsBy(parentSlices, func(cpe policyk8sawsv1.ClusterPolicyEndpoint) bool {
			return lo.ContainsBy(cpe.Spec.PodSelectorEndpoints, func(ep policyk8sawsv1.PodEndpoint) bool {
				return ep.Name == pod.Name && ep.Namespace == pod.Namespace && string(ep.PodIP) == podIP &&
					nodeIP.Equal(net.ParseIP(string(ep.HostIP)))
			})
		})
		if !listed {
			continue
		}
		parentCPEList := lo.Map(parentSlices, func(cpe policyk8sawsv1.ClusterPolicyEndpoint, _ int) string { return cpe.Name })
		log().Infof("Fast path: pod %s is listed by ClusterNetworkPolicy %s, binding podIdentifier %s", pod, parentCNP, podIdentifier)
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToClusterPolicyEndpointMap,
			&r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCPEList)
		for _, cpeName := range parentCPEList {
			addTrackedIdentifier(&r.clusterNetworkPolicyToPodIdentifierMap, utils.GetParentNPNameFromPEName(cpeName), podIdentifier)
			addSelectedPod(&r.ClusterPolicyEndpointSelectorMap, cpeName, pod)
		}
		bound = true
	}
	return bound
}

// addTrackedIdentifier adds podIdentifier to a policy's tracked identifier set. The set is
// replaced, not modified in place: readers load it without a lock.
func addTrackedIdentifier(trackedSets *sync.Map, key, podIdentifier string) {
	var current []string
	if value, ok := trackedSets.Load(key); ok {
		current = value.([]string)
	}
	if lo.Contains(current, podIdentifier) {
		return
	}
	trackedSets.Store(key, append(append([]string(nil), current...), podIdentifier))
}

// addSelectedPod adds pod to a (Cluster)PolicyEndpoint's selected-pod entry.
func addSelectedPod(selectorMap *sync.Map, key string, pod types.NamespacedName) {
	var current []npatypes.Pod
	if value, ok := selectorMap.Load(key); ok {
		current = value.([]npatypes.Pod)
	}
	if lo.ContainsBy(current, func(p npatypes.Pod) bool { return p.NamespacedName == pod }) {
		return
	}
	selectorMap.Store(key, append(append([]npatypes.Pod(nil), current...), npatypes.Pod{NamespacedName: pod}))
}

// reconcileNamespace reconciles every PolicyEndpoint in a namespace, after a pod there
// changed identity, so bindings of its old identity are pruned and its new one is bound.
func (r *PolicyEndpointsReconciler) reconcileNamespace(ctx context.Context, namespace string) error {
	policyEndpointList := &policyk8sawsv1.PolicyEndpointList{}
	if err := r.k8sClient.List(ctx, policyEndpointList, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list PolicyEndpoints in %s: %w", namespace, err)
	}
	var errs error
	for _, pe := range policyEndpointList.Items {
		_, err := r.Reconcile(ctx, ctrlRequest(pe.Namespace, pe.Name))
		errs = errors.Join(errs, err)
	}
	return errs
}

// reconcileListing reconciles every ClusterPolicyEndpoint that lists pod.
func (r *ClusterPolicyEndpointsReconciler) reconcileListing(ctx context.Context, pod types.NamespacedName) error {
	cpeList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	if err := r.k8sClient.List(ctx, cpeList); err != nil {
		return fmt.Errorf("list ClusterPolicyEndpoints: %w", err)
	}
	var errs error
	for _, cpe := range cpeList.Items {
		listed := lo.ContainsBy(cpe.Spec.PodSelectorEndpoints, func(ep policyk8sawsv1.PodEndpoint) bool {
			return ep.Name == pod.Name && ep.Namespace == pod.Namespace
		})
		if !listed {
			continue
		}
		_, err := r.Reconcile(ctx, ctrlRequest("", cpe.Name))
		errs = errors.Join(errs, err)
	}
	return errs
}
