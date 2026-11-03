/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// Buckets for latency
	clusterPolicyProgrammingLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "awsnodeagent_cluster_policy_programming_latency_seconds",
			Help: "E2E latency from NPC ClusterPolicyEndpoint change to NPA eBPF map programming, in seconds",
			Buckets: append(append(append(
				prometheus.LinearBuckets(0.25, 0.25, 2), // 0.25, 0.50
				prometheus.LinearBuckets(1, 1, 59)...),  // 1, 2, 3, ..., 59
				prometheus.LinearBuckets(60, 5, 12)...), // 60, 65, 70, ..., 115
				prometheus.LinearBuckets(120, 30, 7)...), // 120, 150, 180, ..., 300
		},
	)
	clusterPolicyPrometheusRegistered = false
)

func clusterPolicyPrometheusRegister() {
	if !clusterPolicyPrometheusRegistered {
		metrics.Registry.MustRegister(clusterPolicyProgrammingLatency)
		clusterPolicyPrometheusRegistered = true
	}
}

// NewClusterPolicyEndpointsReconciler constructs new ClusterPolicyEndpointReconciler
func NewClusterPolicyEndpointsReconciler(k8sClient client.Client, nodeIP string, ebpfClient ebpf.BpfClient) *ClusterPolicyEndpointsReconciler {
	r := &ClusterPolicyEndpointsReconciler{
		k8sClient:        k8sClient,
		nodeIP:           nodeIP,
		ebpfClient:       ebpfClient,
		trackerStartTime: time.Now(),
	}
	clusterPolicyPrometheusRegister()
	return r
}

// ClusterPolicyEndpointsReconciler reconciles an ClusterPolicyEndpoint object
type ClusterPolicyEndpointsReconciler struct {
	// k8sClient reads ClusterPolicyEndpoints with client.UnsafeDisableDeepCopy: returned objects
	// are shared with the informer cache and must not be mutated.
	k8sClient client.Client
	scheme    *runtime.Scheme
	nodeIP    string
	// trackerStartTime records when this reconciler started. Used to filter
	// stale ClusterPolicyEndpoint annotations and avoid emitting artificially high
	// E2E latency on restart
	trackerStartTime time.Time
	// lastObservedTriggerTimes maps CPE name (cluster-scoped, so name alone is
	// unique) to the last last-change-trigger-time annotation value consumed,
	// so each trigger time is observed at most once
	lastObservedTriggerTimes sync.Map

	// Maps pod Identifier to list of ClusterPolicyEndpoint resources
	podIdentifierToClusterPolicyEndpointMap      sync.Map
	podIdentifierToClusterPolicyEndpointMapMutex sync.Mutex
	// Maps ClusterPolicyEndpoint resource with a list of local pods (cluster-scoped)
	ClusterPolicyEndpointSelectorMap sync.Map
	// Maps ClusterNetworkPolicy to list of selected pod Identifiers
	clusterNetworkPolicyToPodIdentifierMap sync.Map

	ebpfClient ebpf.BpfClient
	// identities resolves local pods to their label identity (see identity.go). Nil means
	// defaultIdentityResolver.
	identities podidentity.Resolver
	// startupGate, when set, is closed once the startup sweep has adopted this node's pods
	// onto their label identities, so reconciles do not attach pods ahead of it.
	startupGate <-chan struct{}
	// bindMu serializes reconciles with bindLocalPodByMembership, as on the namespaced side.
	bindMu sync.Mutex
}

// SetIdentityResolver sets the resolver for local pod identities.
func (r *ClusterPolicyEndpointsReconciler) SetIdentityResolver(resolver podidentity.Resolver) {
	r.identities = resolver
}

// SetStartupGate makes reconciles wait until gate is closed.
func (r *ClusterPolicyEndpointsReconciler) SetStartupGate(gate <-chan struct{}) {
	r.startupGate = gate
}

func (r *ClusterPolicyEndpointsReconciler) resolver() podidentity.Resolver {
	if r.identities == nil {
		return defaultIdentityResolver()
	}
	return r.identities
}

func (r *ClusterPolicyEndpointsReconciler) knownIdentity(ctx context.Context) identityFunc {
	return func(pod types.NamespacedName) (string, bool) {
		return knownPodIdentity(ctx, r.resolver(), r.ebpfClient, pod)
	}
}

func (r *ClusterPolicyEndpointsReconciler) targetIdentity(ctx context.Context) identityFunc {
	return func(pod types.NamespacedName) (string, bool) {
		podIdentifier, _, err := targetPodIdentity(ctx, r.resolver(), r.ebpfClient, pod)
		return podIdentifier, err == nil
	}
}

//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.aws,resources=clusterpolicyendpoints/status,verbs=get

func (r *ClusterPolicyEndpointsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log().Infof("Received a new reconcile request for ClusterPolicyEndpoint %v", req)
	if err := waitForStartupGate(ctx, r.startupGate); err != nil {
		return ctrl.Result{}, err
	}
	r.bindMu.Lock()
	defer r.bindMu.Unlock()
	if err := r.reconcile(ctx, req); err != nil {
		log().Errorf("ClusterPolicyEndpoint reconcile error: %v", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ClusterPolicyEndpointsReconciler) reconcile(ctx context.Context, req ctrl.Request) error {
	ClusterPolicyEndpoint := &policyk8sawsv1.ClusterPolicyEndpoint{}
	// Cluster-scoped: use only name, no namespace
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: req.Name}, ClusterPolicyEndpoint, client.UnsafeDisableDeepCopy); err != nil {
		if apierrors.IsNotFound(err) {
			return r.cleanUpClusterPolicyEndpoint(ctx, req)
		}
		log().Errorf("Unable to get cluster policy endpoint spec for ClusterPolicyendpoint %s: %v", req.Name, err)
		return err
	}
	if !ClusterPolicyEndpoint.DeletionTimestamp.IsZero() {
		return r.cleanUpClusterPolicyEndpoint(ctx, req)
	}
	return r.reconcileClusterPolicyEndpoint(ctx, ClusterPolicyEndpoint)
}

func (r *ClusterPolicyEndpointsReconciler) cleanUpClusterPolicyEndpoint(ctx context.Context, req ctrl.Request) error {
	log().Infof("Clean Up ClusterPolicyEndpoint resources for name: %s", req.Name)

	r.lastObservedTriggerTimes.Delete(req.Name)

	parentCNPName := utils.GetParentNPNameFromPEName(req.Name)
	resourceName := req.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, resolveErr, err :=
		r.deriveTargetPodsForParentCNP(ctx, parentCNPName, resourceName)
	if err != nil {
		return err
	}

	// Remove the deleted CPE's name from every identifier that recorded it. Derive prunes
	// names only for identifiers that went stale, i.e. ones the parent no longer selects, so
	// an identifier still selected via a sibling CPE keeps this name. Later reconciles read
	// these entries, so the departing name has to be scrubbed here. Every identifier is
	// visited, not just those of the pods the selector map recorded, which may be deleted.
	scrubPolicyEndpointName(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, resourceName)

	log().Infof("cleanUpClusterPolicyEndpoint: Pods to cleanup - %d and Pods to be updated - %d", len(podsToBeCleanedUp), len(targetPods))

	_, updateErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, req.Name, targetPods, targetPodIdentifiers, false)
	if updateErr != nil {
		log().Errorf("failed to update cluster policy bpf probes for policy endpoint %s : %v", req.Name, updateErr)
	}
	failedCleanups, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, req.Name, podsToBeCleanedUp, targetPodIdentifiers, true)
	if cleanupErr != nil {
		log().Errorf("failed to clean up cluster policy bpf probes for policy endpoint %s : %v", req.Name, cleanupErr)
	}

	// Same tracking as reconcileClusterPolicyEndpoint.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers, r.knownIdentity(ctx))
	r.commitClusterPolicyEndpointState(resourceName, trackedPods, trackedPodIdentifiers, parentCPEList)

	// Until every cleanup succeeds, the deleted CPE's entry holds the ones that failed, so the
	// retry repeats only those. If the CPE is in parentCPEList (its deletion is in progress,
	// or it is the parent's last CPE), the commit above has already written its entry.
	err = errors.Join(updateErr, cleanupErr, resolveErr)
	if !slices.Contains(parentCPEList, resourceName) {
		// Gate on the failures themselves, not on err: updateErr can be set with nothing owed
		// a cleanup, and storing an empty set would leave an entry keyed by a deleted CPE.
		if len(failedCleanups) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(resourceName, failedCleanups)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(resourceName)
		}
	}
	return err
}

func (r *ClusterPolicyEndpointsReconciler) reconcileClusterPolicyEndpoint(ctx context.Context, ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint) error {
	log().Infof("Processing Cluster Policy Endpoint Name: %s", ClusterPolicyEndpoint.Name)

	parentCNPName := ClusterPolicyEndpoint.Spec.PolicyRef.Name
	resourceName := ClusterPolicyEndpoint.Name

	targetPods, targetPodIdentifiers, podsToBeCleanedUp, parentCPEList, clusterWidePodIdentifiers, resolveErr, err :=
		r.deriveTargetPodsForParentCNP(ctx, parentCNPName, resourceName)
	if err != nil {
		return err
	}

	// Programming runs whether or not cleanup succeeded, so a failing cleanup does not hold
	// back the other pods this CPE selects.
	failedCleanups, cleanupErr := r.updateClusterPolicyEnforcementStatusForPods(ctx, ClusterPolicyEndpoint.Name, podsToBeCleanedUp, targetPodIdentifiers, false)
	if cleanupErr != nil {
		log().Errorf("failed to update cluster policy enforcement status for existing pods: %v", cleanupErr)
	}

	// Track the pods programmed below, so they can be cleaned up later, and the pods whose
	// cleanup failed, so the retry and the CPE delete flow still find them.
	trackedPods, trackedPodIdentifiers := trackFailedCleanups(targetPods, failedCleanups, clusterWidePodIdentifiers, r.knownIdentity(ctx))
	r.commitClusterPolicyEndpointState(resourceName, trackedPods, trackedPodIdentifiers, parentCPEList)

	var programmingErr error
	for podIdentifier := range targetPodIdentifiers {
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, ClusterPolicyEndpoint.Name, false)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s for podIdentifier %s: %v", ClusterPolicyEndpoint.Name, podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
			continue
		}
		if err := r.configureClusterPolicyBPFProbes(podIdentifier, targetPods, ingressRules, egressRules, r.targetIdentity(ctx)); err != nil {
			log().Errorf("Error configuring Cluster Policy eBPF Probes for podIdentifier %s: %v", podIdentifier, err)
			programmingErr = errors.Join(programmingErr, err)
		}
	}

	// Observed on the first pass where cleanup and programming both succeed. A failing pass
	// leaves the trigger time unconsumed so the retry that finally lands the change records
	// it, retry delay included -- otherwise the histogram would drop exactly the slow
	// recover-after-failure cases it most needs to show.
	r.observeClusterPolicyProgrammingLatency(ClusterPolicyEndpoint, cleanupErr == nil && programmingErr == nil && resolveErr == nil)

	return errors.Join(cleanupErr, programmingErr, resolveErr)
}

// observeClusterPolicyProgrammingLatency emits the E2E latency histogram from
// the last-change-trigger-time annotation. Each annotation value is observed at
// most once per CPE: it is consumed once the change has landed, so stale
// rewrites/resyncs/relists never re-observe it.
//
// A pass that has not landed the change leaves the annotation unconsumed, so the
// later pass that does land it reports the full time including any retry delay.
func (r *ClusterPolicyEndpointsReconciler) observeClusterPolicyProgrammingLatency(cpe *policyk8sawsv1.ClusterPolicyEndpoint, programmingSucceeded bool) {
	if cpe.Annotations == nil {
		return
	}
	triggerTimeStr, ok := cpe.Annotations[LastChangeTriggerTimeAnnotation]
	if !ok || triggerTimeStr == "" {
		return
	}
	triggerTime, err := time.Parse(time.RFC3339Nano, triggerTimeStr)
	if err != nil {
		log().Debugf("Failed to parse %s annotation: %v", LastChangeTriggerTimeAnnotation, err)
		return
	}
	if !triggerTime.After(r.trackerStartTime) {
		return
	}
	if prev, ok := r.lastObservedTriggerTimes.Load(cpe.Name); ok && prev.(string) == triggerTimeStr {
		return
	}
	if !programmingSucceeded {
		// Left unconsumed on purpose: the pass that lands the change observes it.
		log().Debugf("Deferring E2E cluster policy programming latency for CPE %s: change has not landed yet", cpe.Name)
		return
	}
	// Consume before the suppression check below: the change has landed, so a
	// clock-skew-suppressed observation must not be re-emitted (inflated) by a
	// later resync of the same annotation.
	r.lastObservedTriggerTimes.Store(cpe.Name, triggerTimeStr)
	latency := time.Since(triggerTime).Seconds()
	if latency < 0 {
		// Clock skew between NPC (control plane) and this node
		log().Debugf("Skipping negative E2E cluster policy programming latency %.3fs for CPE %s", latency, cpe.Name)
		return
	}
	clusterPolicyProgrammingLatency.Observe(latency)
	log().Debugf("E2E cluster policy programming latency: %.3fs for CPE %s", latency, cpe.Name)
}

func (r *ClusterPolicyEndpointsReconciler) configureClusterPolicyBPFProbes(podIdentifier string, targetPods []npatypes.Pod, ingressRules, egressRules []fwrp.EbpfFirewallRules, identityOf identityFunc) error {
	configureProbesErr := attachProbesForIdentifier(r.ebpfClient, podIdentifier, targetPods, identityOf)

	// AttacheBPFProbes skips pods already deleted from the node, so the CPE can still list a
	// pod that has no programs here. There is nothing to program until a new pod attaches.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy programming for podIdentifier %s: no eBPF context registered", podIdentifier)
		return configureProbesErr
	}

	// Program whatever did attach. updateClusterPolicyBPFMaps logs its own failure, and the
	// returned error is logged again by the caller, so it is not logged a third time here.
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
		return errors.Join(configureProbesErr, fmt.Errorf("cluster policy map updates failed for podIdentifier %s: %w", podIdentifier, err))
	}
	return configureProbesErr
}

func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyBPFMaps(podIdentifier string, ingressRules, egressRules []fwrp.EbpfFirewallRules) error {

	state := ebpf.POLICIES_APPLIED

	err := r.ebpfClient.UpdateClusterPolicyEbpfMaps(podIdentifier, ingressRules, egressRules)
	if err != nil {
		log().Errorf("Cluster Policy Map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}

	if len(ingressRules) == 0 && len(egressRules) == 0 {
		// Default state for cluster network policies when no rules are applied
		state = ebpf.DEFAULT_ALLOW
	}

	err = r.ebpfClient.UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, state, true, true)
	if err != nil {
		log().Errorf("Cluster Policy pod state maps update(s) failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}

	defaultState := ebpf.DEFAULT_ALLOW
	if utils.IsStrictMode(r.ebpfClient.GetNetworkPolicyMode()) {
		defaultState = ebpf.DEFAULT_DENY
	}

	// TODO: Can be optimized to avoid redundant createIfNotExists calls
	if err := r.ebpfClient.CreatePodStateEbpfEntryIfNotExists(podIdentifier, ebpf.POD_STATE_MAP_KEY, defaultState); err != nil {
		log().Errorf("Pod-state seed failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}
	return nil
}

func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyIngressAndEgressFirewallRules(ctx context.Context, podIdentifier string, resourceName string, isDeleteFlow bool) ([]fwrp.EbpfFirewallRules, []fwrp.EbpfFirewallRules, error) {

	var clusterPolicyIngressRules, clusterPolicyEgressRules []fwrp.EbpfFirewallRules
	currentCPE := &policyk8sawsv1.ClusterPolicyEndpoint{}

	if ClusterPolicyEndpointList, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		log().Infof("Total number of ClusterPolicyEndpoint resources for podIdentifier %s are %d", podIdentifier, len(ClusterPolicyEndpointList.([]string)))
		for _, ClusterPolicyEndpointResource := range ClusterPolicyEndpointList.([]string) {
			// Cluster-scoped: no namespace
			cpeNamespacedName := types.NamespacedName{Name: ClusterPolicyEndpointResource}

			if isDeleteFlow {
				deletedCPEParentCNPName := utils.GetParentNPNameFromPEName(resourceName)
				currentCPEParentCNPName := utils.GetParentNPNameFromPEName(ClusterPolicyEndpointResource)
				if deletedCPEParentCNPName == currentCPEParentCNPName {
					log().Debugf("CPE belongs to same CNP. Ignore and move on since it's a delete flow deletedCPE %s currentCPE %s", resourceName, ClusterPolicyEndpointResource)
					continue
				}
			}

			if err := r.k8sClient.Get(ctx, cpeNamespacedName, currentCPE, client.UnsafeDisableDeepCopy); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, nil, err
			}

			// currentCPE is shared with the informer cache (UnsafeDisableDeepCopy). slices.Clip
			// makes appends to L4Info reallocate, but its existing elements, and the
			// Protocol/Port/EndPort pointers inside each Port, still belong to the cache: rule
			// processing must treat them as read-only. Guarded by
			// TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged.
			for _, endPointInfo := range currentCPE.Spec.Ingress {
				priority := int(currentCPE.Spec.Priority)
				if currentCPE.Spec.Tier == policyk8sawsv1.BaselineTier {
					priority += fwrp.BASELINE_TIER_PRIORITY_OFFSET
				}
				clusterPolicyIngressRules = append(clusterPolicyIngressRules, fwrp.EbpfFirewallRules{
					Priority: priority,
					Action:   endPointInfo.Action,
					IPCidr:   endPointInfo.CIDR,
					L4Info:   slices.Clip(endPointInfo.Ports),
				})
			}

			for _, endPointInfo := range currentCPE.Spec.Egress {

				if endPointInfo.CIDR == "" && endPointInfo.DomainName == "" {
					log().Warnf("both CIDR and DomainName are empty in PE name %s", currentCPE.Name)
					continue
				}

				if endPointInfo.CIDR == "" {
					log().Infof("CIDR is empty, skipping the egress rule %s", currentCPE.Name)
					continue
				}

				priority := int(currentCPE.Spec.Priority)
				if currentCPE.Spec.Tier == policyk8sawsv1.BaselineTier {
					priority += fwrp.BASELINE_TIER_PRIORITY_OFFSET
				}
				clusterPolicyEgressRules = append(clusterPolicyEgressRules, fwrp.EbpfFirewallRules{
					Priority:   priority,
					Action:     endPointInfo.Action,
					DomainName: string(endPointInfo.DomainName),
					IPCidr:     endPointInfo.CIDR,
					L4Info:     slices.Clip(endPointInfo.Ports),
				})
			}
			log().Infof("Total no.of clusterPolicy ingressRules %d egressRules %d", len(clusterPolicyIngressRules), len(clusterPolicyEgressRules))
		}
	}
	return clusterPolicyIngressRules, clusterPolicyEgressRules, nil
}

// deriveTargetPodsForParentCNP scrubs the parent's CPEs out of every stale identifier's
// podIdentifierToClusterPolicyEndpointMap entry so cleanupClusterPolicyPod's presence check
// only sees sibling CPEs from OTHER parents. Leaves ClusterPolicyEndpointSelectorMap and
// clusterNetworkPolicyToPodIdentifierMap untouched for the caller to commit via
// commitClusterPolicyEndpointState once cleanup has run.
//
// resolveErr joins the failures to resolve a selected local pod's identity; those pods are
// left out and the caller requeues. err is a List failure, after which nothing is derived.
func (r *ClusterPolicyEndpointsReconciler) deriveTargetPodsForParentCNP(ctx context.Context, parentCNPName, resourceName string) (newTargetPods []npatypes.Pod,
	podIdentifiers map[string]bool, podsToBeCleanedUp []npatypes.Pod, parentCPEList []string, selectedPodIdentifiers map[string]bool, resolveErr error, err error) {
	var currentPods []npatypes.Pod
	var stalePodIdentifiers []string
	podIdentifiers = make(map[string]bool)
	// Node-local, like podIdentifiers; see deriveTargetPodsForParentNP.
	selectedPodIdentifiers = make(map[string]bool)

	parentCPEObjects, err := r.getClusterPolicyEndpointsOfParentCNP(ctx, parentCNPName)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	log().Infof("Parent Cluster Network Policy resource Name: %s Total Cluster Policy Endpoints for Parent CNP: Count: %d", parentCNPName, len(parentCPEObjects))

	if len(parentCPEObjects) == 0 {
		parentCPEList = []string{resourceName}
	} else {
		parentCPEList = lo.Map(parentCPEObjects, func(cpe policyk8sawsv1.ClusterPolicyEndpoint, _ int) string {
			return cpe.Name
		})
		for _, currentCPE := range parentCPEObjects {
			currentTargetPods, currentPodIdentifiers, cpeResolveErr := r.deriveClusterPolicyTargetPods(ctx, &currentCPE, parentCPEList)
			resolveErr = errors.Join(resolveErr, cpeResolveErr)
			newTargetPods = append(newTargetPods, currentTargetPods...)
			for pid := range currentPodIdentifiers {
				podIdentifiers[pid] = true
				selectedPodIdentifiers[pid] = true
			}
		}
	}

	// parentCNPName is derived from the resource name to maintain consistency with the read and write operations on Maps
	parentCNPName = utils.GetParentNPNameFromPEName(resourceName)
	stalePodIdentifiers = utils.DeriveStalePodIdentifiers(&r.clusterNetworkPolicyToPodIdentifierMap, parentCNPName, selectedPodIdentifiers)

	// Commit records the parent's pods under every one of its CPEs, so a CPE reconciled before
	// it has an entry of its own, such as a new slice, finds them under a sibling.
	for _, cpeName := range lo.Uniq(append([]string{resourceName}, parentCPEList...)) {
		if existingPods, ok := r.ClusterPolicyEndpointSelectorMap.Load(cpeName); ok {
			currentPods = append(currentPods, existingPods.([]npatypes.Pod)...)
		}
	}
	// Dedupe on identity, not on the whole struct: the same pod can be recorded under two
	// slices with different PodIPs (a StatefulSet pod keeps its name across recreation but
	// not its address), and GetPodListToBeCleanedUp matches on NamespacedName, so both copies
	// would land in podsToBeCleanedUp and the pod would be cleaned up twice.
	currentPods = lo.UniqBy(currentPods, func(pod npatypes.Pod) types.NamespacedName {
		return pod.NamespacedName
	})

	// Prune by exact ClusterPolicyEndpoint name rather than by derived parent CNP name.
	// GetParentNPNameFromPEName is lossy under GenerateName truncation, so a parent-wide
	// match can drop a different CNP's slices -- and for cluster policies those carry Deny
	// rules. Exact names can only ever under-delete.
	//
	// The live list alone is not sufficient: a stale identifier still holds the slice names
	// from the reconcile that last selected it, and the CPE being deleted is by definition no
	// longer in the live list. Prune against the live slices PLUS resourceName, which on the
	// delete path is the departing CPE's own name (and is already a member of parentCPEList
	// on the reconcile path, making it a no-op).
	pruneNames := parentCPEList
	if !slices.Contains(pruneNames, resourceName) {
		pruneNames = append(slices.Clone(parentCPEList), resourceName)
	}
	for _, podIdentifier := range stalePodIdentifiers {
		for _, cpeName := range pruneNames {
			utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, cpeName)
		}
	}

	if len(currentPods) > 0 {
		podsToBeCleanedUp = utils.GetPodListToBeCleanedUp(currentPods, newTargetPods, podIdentifiers, r.knownIdentity(ctx))
	}
	return newTargetPods, podIdentifiers, podsToBeCleanedUp, parentCPEList, selectedPodIdentifiers, resolveErr, nil
}

// deriveClusterPolicyTargetPods derives the local pods a CPE selects and binds their
// identities to the parent's CPEs. Pods on other nodes are skipped, as in deriveTargetPods.
//
// A CPE carries no pod selector, so a listed pod is bound as listed. Two pods share an
// identity only if their namespace and labels match, which is everything a cluster policy
// selects on, so binding one binds exactly the pods the policy selects.
func (r *ClusterPolicyEndpointsReconciler) deriveClusterPolicyTargetPods(ctx context.Context, ClusterPolicyEndpoint *policyk8sawsv1.ClusterPolicyEndpoint,
	parentCPEList []string) ([]npatypes.Pod, map[string]bool, error) {
	var targetPods []npatypes.Pod
	var resolveErr error
	podIdentifiers := make(map[string]bool)

	nodeIP := net.ParseIP(r.nodeIP)
	for _, pod := range ClusterPolicyEndpoint.Spec.PodSelectorEndpoints {
		if !nodeIP.Equal(net.ParseIP(string(pod.HostIP))) {
			continue
		}
		podName := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}
		podIdentifier, res, err := targetPodIdentity(ctx, r.resolver(), r.ebpfClient, podName)
		switch {
		case errors.Is(err, podidentity.ErrPodNotFound):
			log().Infof("Skipping pod %s listed by CPE %s: deleted", podName, ClusterPolicyEndpoint.Name)
			continue
		case errors.Is(err, errIdentityMovePending):
			log().Infof("Skipping pod %s listed by CPE %s: %v", podName, ClusterPolicyEndpoint.Name, err)
			continue
		case err != nil:
			resolveErr = errors.Join(resolveErr, fmt.Errorf("resolve identity of pod %s: %w", podName, err))
			continue
		}
		if res.HostNetwork {
			continue
		}
		targetPods = append(targetPods, npatypes.Pod{NamespacedName: podName, PodIP: pod.PodIP})
		podIdentifiers[podIdentifier] = true
		utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToClusterPolicyEndpointMap, &r.podIdentifierToClusterPolicyEndpointMapMutex, podIdentifier, parentCPEList)
	}
	return targetPods, podIdentifiers, resolveErr
}

// updateClusterPolicyEnforcementStatusForPods returns the pods whose cleanup failed.
//
// Despite the name, this is not cleanup-only: cleanUpClusterPolicyEndpoint also calls it on
// targetPods, the pods the parent policy still selects. For those, cleanupClusterPolicyPod
// re-derives the surviving rules and reprograms them, which is what drops the departing
// slice's contribution while leaving the rest of the parent's policy in place.
func (r *ClusterPolicyEndpointsReconciler) updateClusterPolicyEnforcementStatusForPods(ctx context.Context, ClusterPolicyEndpointName string, cleanupPods []npatypes.Pod, podIdentifiers map[string]bool, isDeleteFlow bool) ([]npatypes.Pod, error) {
	var failed []npatypes.Pod
	var err error
	for _, cleanupPod := range cleanupPods {
		if cleanupErr := r.cleanupClusterPolicyPod(ctx, cleanupPod, ClusterPolicyEndpointName, isDeleteFlow); cleanupErr != nil {
			log().Errorf("Cluster Policy Cleanup/Update unsuccessful for Pod Name: %s Namespace: %s ", cleanupPod.Name, cleanupPod.Namespace)
			failed = append(failed, cleanupPod)
			err = errors.Join(err, cleanupErr)
		}
	}
	return failed, err
}

func (r *ClusterPolicyEndpointsReconciler) cleanupClusterPolicyPod(ctx context.Context, targetPod npatypes.Pod, clusterPolicyEndpoint string, isDeleteFlow bool) error {
	podIdentifier, known := knownPodIdentity(ctx, r.resolver(), r.ebpfClient, targetPod.NamespacedName)
	if !known {
		log().Debugf("Skipping cluster policy cleanup for pod %s: no known identity", targetPod.NamespacedName)
		return nil
	}

	// The map consulted below can outlive this node's programs for the identifier. Only the
	// eBPF context tells, and every write below needs it, so when it is gone there is nothing
	// here to clean up.
	if !r.ebpfClient.HasBPFContext(podIdentifier) {
		log().Debugf("Skipping cluster policy cleanup for podIdentifier %s: no eBPF context registered", podIdentifier)
		return nil
	}

	if _, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		// A sibling CPE (from this or another parent CNP) still targets the identifier —
		// recompute rules from what remains.
		ingressRules, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, clusterPolicyEndpoint, isDeleteFlow)
		if err != nil {
			log().Errorf("Error Parsing cluster policy Endpoint resource %s: %v", clusterPolicyEndpoint, err)
			return err
		}
		if err := r.updateClusterPolicyBPFMaps(podIdentifier, ingressRules, egressRules); err != nil {
			log().Errorf("cluster policy map update(s) failed for podIdentifier %s: %v", podIdentifier, err)
			return err
		}
		return nil
	}

	// Nothing selects this identifier; clear its eBPF maps.
	log().Debugf("No cluster policies left for podIdentifier %s, clearing cluster policy maps", podIdentifier)
	if err := r.updateClusterPolicyBPFMaps(podIdentifier, nil, nil); err != nil {
		log().Errorf("cluster policy map clear failed for podIdentifier %s: %v", podIdentifier, err)
		return err
	}
	return nil
}

// commitClusterPolicyEndpointState updates the two maps derive left untouched. Runs after
// cleanup. Callers also pass the pods whose cleanup failed, so the retry derives them as
// stale again. Keys clusterNetworkPolicyToPodIdentifierMap by
// GetParentNPNameFromPEName(resourceName) — the same derivation the reader uses, so writes
// and reads agree when GenerateName truncates the CPE base (CNP names >= 58 chars).
func (r *ClusterPolicyEndpointsReconciler) commitClusterPolicyEndpointState(
	resourceName string,
	newTargetPods []npatypes.Pod,
	clusterWidePodIdentifiers map[string]bool,
	parentCPEList []string,
) {
	for _, cpeName := range parentCPEList {
		if len(newTargetPods) > 0 {
			r.ClusterPolicyEndpointSelectorMap.Store(cpeName, newTargetPods)
		} else {
			r.ClusterPolicyEndpointSelectorMap.Delete(cpeName)
		}
	}

	parentKey := utils.GetParentNPNameFromPEName(resourceName)
	if len(clusterWidePodIdentifiers) == 0 {
		r.clusterNetworkPolicyToPodIdentifierMap.Delete(parentKey)
		return
	}
	clusterWidePodIdentifiersList := make([]string, 0, len(clusterWidePodIdentifiers))
	for pid := range clusterWidePodIdentifiers {
		clusterWidePodIdentifiersList = append(clusterWidePodIdentifiersList, pid)
	}
	r.clusterNetworkPolicyToPodIdentifierMap.Store(parentKey, clusterWidePodIdentifiersList)
}

// getClusterPolicyEndpointsOfParentCNP returns the CPEs whose PolicyRef.Name matches
// parentCNP. Callers must distinguish an empty result from a List failure — passing a
// nil slice to the "no CPEs left" branch would incorrectly clear eBPF Deny rules on a
// transient API error and open traffic.
func (r *ClusterPolicyEndpointsReconciler) getClusterPolicyEndpointsOfParentCNP(ctx context.Context, parentCNP string) ([]policyk8sawsv1.ClusterPolicyEndpoint, error) {
	ClusterPolicyEndpointList := &policyk8sawsv1.ClusterPolicyEndpointList{}
	// Cluster-scoped: no namespace filter
	if err := r.k8sClient.List(ctx, ClusterPolicyEndpointList, &client.ListOptions{}, client.UnsafeDisableDeepCopy); err != nil {
		log().Errorf("Unable to list ClusterPolicyEndpoints err: %v", err)
		return nil, err
	}

	var parentClusterPolicyEndpoints []policyk8sawsv1.ClusterPolicyEndpoint
	for _, ClusterPolicyEndpoint := range ClusterPolicyEndpointList.Items {
		if ClusterPolicyEndpoint.Spec.PolicyRef.Name == parentCNP {
			parentClusterPolicyEndpoints = append(parentClusterPolicyEndpoints, ClusterPolicyEndpoint)
		}
	}
	return parentClusterPolicyEndpoints, nil
}

func (r *ClusterPolicyEndpointsReconciler) DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx context.Context, podIdentifier string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, error) {

	clusterPolicyIngressRules, clusterPolicyEgressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(ctx, podIdentifier, "", false)
	if err != nil {
		log().Errorf("Error deriving cluster firewall rules: %v", err)
		return clusterPolicyIngressRules, clusterPolicyEgressRules, err
	}

	return clusterPolicyIngressRules, clusterPolicyEgressRules, nil
}

func (r *ClusterPolicyEndpointsReconciler) ArePoliciesAvailableInLocalCache(podIdentifier string) bool {
	if policyEndpointList, ok := r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier); ok {
		if len(policyEndpointList.([]string)) > 0 {
			log().Infof("Active cluster policies available against podIdentifier %s", podIdentifier)
			return true
		}
	}
	return false
}

func (r *ClusterPolicyEndpointsReconciler) GeteBPFClient() ebpf.BpfClient {
	return r.ebpfClient
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPolicyEndpointsReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyk8sawsv1.ClusterPolicyEndpoint{}).
		Complete(r)
}
