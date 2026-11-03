package controllers

import (
	"context"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/podidentity"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// End-to-end tests of label identities through the reconcilers, the pod enforcer, the pod
// identity controller and the startup sweep, against a fake API server read through the
// production resolver.

const (
	labelNodeIP   = "10.0.0.1"
	remoteNodeIP  = "10.0.0.2"
	labelTestNS   = "prod"
	apiClientCIDR = "10.9.0.0/16"
)

type labelFixture struct {
	t        *testing.T
	client   client.Client
	bpf      *ebpf.MockBpfClient
	pe       *PolicyEndpointsReconciler
	cpe      *ClusterPolicyEndpointsReconciler
	enforcer PodEnforcer
}

func newLabelFixture(t *testing.T, objs ...client.Object) *labelFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	fx := &labelFixture{t: t, client: c, bpf: &ebpf.MockBpfClient{AttachFirstPodInPodIdentifier: true}}
	resolver := podidentity.NewAPIResolver(c, c)
	resolver.MarkCacheReady()
	fx.pe = NewPolicyEndpointsReconciler(c, labelNodeIP, fx.bpf, false)
	fx.pe.SetIdentityResolver(resolver)
	fx.cpe = NewClusterPolicyEndpointsReconciler(c, labelNodeIP, fx.bpf)
	fx.cpe.SetIdentityResolver(resolver)
	fx.enforcer = PodEnforcer{Policy: fx.pe, ClusterPolicy: fx.cpe}
	return fx
}

func labelPod(name string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: labelTestNS, Labels: podLabels},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{PodIP: "10.0.1." + string(rune('1'+len(name)%8)), Phase: corev1.PodRunning},
	}
}

func endpoint(name, hostIP string) policyk8sawsv1.PodEndpoint {
	return policyk8sawsv1.PodEndpoint{Name: name, Namespace: labelTestNS, PodIP: "10.0.1.9", HostIP: policyk8sawsv1.NetworkAddress(hostIP)}
}

// ingressPE is a PolicyEndpoint selecting podSelector, isolated for ingress, with an
// optional allow from apiClientCIDR.
func ingressPE(name string, podSelector map[string]string, allow bool, pods ...policyk8sawsv1.PodEndpoint) *policyk8sawsv1.PolicyEndpoint {
	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-abcde", Namespace: labelTestNS},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:          &metav1.LabelSelector{MatchLabels: podSelector},
			PolicyRef:            policyk8sawsv1.PolicyReference{Name: name, Namespace: labelTestNS},
			PodIsolation:         []networking.PolicyType{networking.PolicyTypeIngress},
			PodSelectorEndpoints: pods,
		},
	}
	if allow {
		pe.Spec.Ingress = []policyk8sawsv1.EndpointInfo{{CIDR: apiClientCIDR}}
	}
	return pe
}

func (fx *labelFixture) reconcilePE(pe *policyk8sawsv1.PolicyEndpoint) {
	fx.t.Helper()
	_, err := fx.pe.Reconcile(context.Background(), ctrlRequest(pe.Namespace, pe.Name))
	require.NoError(fx.t, err)
}

func (fx *labelFixture) attach(name string, podIdentifier string) {
	fx.t.Helper()
	_, err := fx.bpf.AttacheBPFProbes(types.NamespacedName{Name: name, Namespace: labelTestNS}, podIdentifier, 1, true)
	require.NoError(fx.t, err)
}

func (fx *labelFixture) boundPolicyEndpoints(podIdentifier string) []string {
	value, ok := fx.pe.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
	if !ok {
		return nil
	}
	return value.([]string)
}

func identityOfLabels(podLabels map[string]string) string {
	return utils.PodIdentity(podLabels, labelTestNS)
}

var (
	dbLabels   = map[string]string{"app": "db"}
	evilLabels = map[string]string{"app": "evil"}
	dbID       = identityOfLabels(dbLabels)
	evilID     = identityOfLabels(evilLabels)
)

// The Robosec finding: default-deny selects every pod and db-policy allows the API tier to
// reach app=db. db-evil's name collides with db-0's, but it must get default-deny only.
func TestLabelIdentity_CollidingNameDoesNotInheritAllowRules(t *testing.T) {
	defaultDeny := ingressPE("default-deny", map[string]string{}, false, endpoint("db-0", labelNodeIP), endpoint("db-evil", labelNodeIP))
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-0", labelNodeIP))
	fx := newLabelFixture(t, labelPod("db-0", dbLabels), labelPod("db-evil", evilLabels), defaultDeny, dbPolicy)
	fx.attach("db-0", dbID)
	fx.attach("db-evil", evilID)

	fx.reconcilePE(defaultDeny)
	fx.reconcilePE(dbPolicy)

	require.NotEqual(t, dbID, evilID)
	assert.ElementsMatch(t, []string{defaultDeny.Name, dbPolicy.Name}, fx.boundPolicyEndpoints(dbID))
	assert.Equal(t, []string{defaultDeny.Name}, fx.boundPolicyEndpoints(evilID), "db-policy must not bind db-evil")
	assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: apiClientCIDR}}, fx.bpf.IngressByIdentifier[dbID])
	assert.Empty(t, fx.bpf.IngressByIdentifier[evilID], "db-evil is ingress-isolated with no allow")
	assert.Equal(t, ebpf.POLICIES_APPLIED, fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: evilID, MapKey: ebpf.POD_STATE_MAP_KEY}])
}

// StatefulSet db and DaemonSet db in one namespace: their pods reduce to the same name
// prefix, but the policy for the StatefulSet's labels must not reach the DaemonSet's pods.
func TestLabelIdentity_SameNamedControllersOfDifferentKinds(t *testing.T) {
	stsLabels := map[string]string{"app": "db", "role": "primary"}
	dsLabels := map[string]string{"app": "db-agent"}
	stsPolicy := ingressPE("db-primary", stsLabels, true, endpoint("db-0", labelNodeIP))
	fx := newLabelFixture(t, labelPod("db-0", stsLabels), labelPod("db-x7k2p", dsLabels), stsPolicy)
	fx.attach("db-0", identityOfLabels(stsLabels))
	fx.attach("db-x7k2p", identityOfLabels(dsLabels))

	fx.reconcilePE(stsPolicy)

	assert.Equal(t, []string{stsPolicy.Name}, fx.boundPolicyEndpoints(identityOfLabels(stsLabels)))
	assert.Empty(t, fx.boundPolicyEndpoints(identityOfLabels(dsLabels)))
	assert.NotContains(t, fx.bpf.IngressByIdentifier, identityOfLabels(dsLabels))
}

// A PolicyEndpoint can lag a relabel. A listed pod whose current labels no longer match the
// selector is not bound, so the policy does not reach the pods sharing its identity.
func TestLabelIdentity_StaleListingIsNotBound(t *testing.T) {
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-evil", labelNodeIP))
	fx := newLabelFixture(t, labelPod("db-evil", evilLabels), dbPolicy)
	fx.attach("db-evil", evilID)

	fx.reconcilePE(dbPolicy)

	assert.Empty(t, fx.boundPolicyEndpoints(evilID))
	assert.NotContains(t, fx.bpf.IngressByIdentifier, evilID)
}

// Pods on other nodes are never bound here: no labels to check, and no local cleanup for
// their entries (#613).
func TestLabelIdentity_RemotePodsAreNotTracked(t *testing.T) {
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-0", remoteNodeIP))
	fx := newLabelFixture(t, labelPod("db-0", dbLabels), dbPolicy)

	fx.reconcilePE(dbPolicy)

	assert.Equal(t, 0, sizeOfSyncMap(&fx.pe.podIdentifierToPolicyEndpointMap))
	assert.Empty(t, fx.bpf.AttachedIdentifiers)
}

// A pod attached under another identity than its labels give (a relabel the pod identity
// controller has not processed yet) is bound under neither: the attached identity is shared
// with pods that still have the old labels.
func TestLabelIdentity_PendingMoveIsNotBound(t *testing.T) {
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-0", labelNodeIP))
	fx := newLabelFixture(t, labelPod("db-0", dbLabels), dbPolicy)
	fx.attach("db-0", evilID)

	fx.reconcilePE(dbPolicy)

	assert.Empty(t, fx.boundPolicyEndpoints(evilID))
	assert.Empty(t, fx.boundPolicyEndpoints(dbID))
}

// The pod-start fast path binds by selector before NPC lists the pod. When a reconcile then
// finds the pod not listed after all, it prunes the binding and reprograms the identity.
func TestLabelIdentity_FastPathBindingIsPrunedWhenNotListed(t *testing.T) {
	dbPolicy := ingressPE("db-policy", dbLabels, true)
	fx := newLabelFixture(t, labelPod("db-0", dbLabels), dbPolicy)

	require.NoError(t, fx.enforcer.EnforceNewPod(context.Background(), types.NamespacedName{Name: "db-0", Namespace: labelTestNS}, 1, "standard"))
	require.Equal(t, []string{dbPolicy.Name}, fx.boundPolicyEndpoints(dbID), "fast path bound by selector")
	require.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: apiClientCIDR}}, fx.bpf.IngressByIdentifier[dbID])

	// NPC's view: the policy selects nothing (say its selector was edited before the PE caught up).
	fx.reconcilePE(dbPolicy)

	assert.Empty(t, fx.boundPolicyEndpoints(dbID), "binding pruned by the reconcile")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: dbID, MapKey: ebpf.POD_STATE_MAP_KEY}],
		"identity reprogrammed to the mode default")
}

// A relabel moves the pod to its new identity, then the namespace is reconciled: the old
// identity's bindings go, the new one gets the policies selecting the new labels.
func TestLabelIdentity_RelabelMovesPodAndRebinds(t *testing.T) {
	defaultDeny := ingressPE("default-deny", map[string]string{}, false, endpoint("db-0", labelNodeIP))
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-0", labelNodeIP))
	pod := labelPod("db-0", dbLabels)
	fx := newLabelFixture(t, pod, defaultDeny, dbPolicy)
	fx.attach("db-0", dbID)
	fx.reconcilePE(defaultDeny)
	fx.reconcilePE(dbPolicy)
	require.ElementsMatch(t, []string{defaultDeny.Name, dbPolicy.Name}, fx.boundPolicyEndpoints(dbID))

	// Relabel db-0 out of db-policy. NPC has not updated db-policy's listing yet.
	pod.Labels = map[string]string{"app": "maintenance"}
	require.NoError(t, fx.client.Update(context.Background(), pod))
	newID := identityOfLabels(pod.Labels)

	podReconciler := NewPodIdentityReconciler(fx.client, fx.enforcer, nil)
	_, err := podReconciler.Reconcile(context.Background(), ctrlRequest(labelTestNS, "db-0"))
	require.NoError(t, err)

	assert.Equal(t, []ebpf.Repoint{{Pod: types.NamespacedName{Name: "db-0", Namespace: labelTestNS}, From: dbID, To: newID}}, fx.bpf.Repoints)
	assert.Contains(t, fx.bpf.LoadedIdentifiers, newID, "maps loaded and programmed before the move")
	assert.Equal(t, []string{defaultDeny.Name}, fx.boundPolicyEndpoints(newID),
		"default-deny follows the pod; db-policy's stale listing does not")
	assert.Empty(t, fx.bpf.IngressByIdentifier[newID])
	assert.Empty(t, fx.boundPolicyEndpoints(dbID), "no pod left on the old identity")
}

// The startup sweep adopts every network-ready local pod onto its label identity, binds by
// selector (namespaced) and by membership (cluster), and only then releases what is unused.
func TestLabelIdentity_StartupSweep(t *testing.T) {
	dbPolicy := ingressPE("db-policy", dbLabels, true, endpoint("db-0", labelNodeIP))
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-deny-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-deny"},
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "db-0", Namespace: labelTestNS, PodIP: "10.0.1.5", HostIP: labelNodeIP},
			},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "0.0.0.0/0", Action: "Deny"}},
		},
	}
	db0 := labelPod("db-0", dbLabels)
	db0.Status.PodIP = "10.0.1.5"
	notReady := labelPod("pending", evilLabels)
	notReady.Status.PodIP = ""
	hostNet := labelPod("hostnet", evilLabels)
	hostNet.Spec.HostNetwork = true
	fx := newLabelFixture(t, db0, labelPod("db-evil", evilLabels), notReady, hostNet, dbPolicy, cpe)

	gate := make(chan struct{})
	sweep := &IdentitySweep{Pods: fx.client, WaitForCacheSync: func(context.Context) bool { return true }, Enforcer: fx.enforcer, Gate: gate}
	require.NoError(t, sweep.Start(context.Background()))

	select {
	case <-gate:
	default:
		t.Fatal("the gate must be closed after the sweep")
	}
	assert.Equal(t, map[types.NamespacedName]string{
		{Name: "db-0", Namespace: labelTestNS}:    dbID,
		{Name: "db-evil", Namespace: labelTestNS}: evilID,
	}, fx.bpf.AttachedIdentifiers, "network-ready, non-host-network pods only")
	assert.Equal(t, []string{dbPolicy.Name}, fx.boundPolicyEndpoints(dbID))
	assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: apiClientCIDR}}, fx.bpf.IngressByIdentifier[dbID],
		"rules programmed before the pod is moved onto the identity")
	assert.True(t, fx.cpe.ArePoliciesAvailableInLocalCache(dbID), "listed by the CPE with its IP: bound by membership")
	assert.False(t, fx.cpe.ArePoliciesAvailableInLocalCache(evilID))
	require.Len(t, fx.bpf.ReleaseKeepSets, 1)
	assert.Equal(t, map[string]bool{dbID: true, evilID: true}, fx.bpf.ReleaseKeepSets[0])
}

func TestLabelIdentity_StartupSweepReleasesNothingAfterAFailure(t *testing.T) {
	fx := newLabelFixture(t, labelPod("db-0", dbLabels))
	fx.bpf.RepointBPFProbesErrFor = map[types.NamespacedName]error{{Name: "db-0", Namespace: labelTestNS}: assert.AnError}

	sweep := &IdentitySweep{Pods: fx.client, Enforcer: fx.enforcer, Gate: make(chan struct{})}
	failed, err := sweep.sweepOnce(context.Background())

	assert.Equal(t, 1, failed)
	assert.Error(t, err)
	assert.Empty(t, fx.bpf.ReleaseKeepSets, "a pod that did not move may still use a program that looks unused")
}

func TestPodIdentityEvents(t *testing.T) {
	base := labelPod("db-0", dbLabels)
	relabeled := base.DeepCopy()
	relabeled.Labels = evilLabels
	readied := base.DeepCopy()
	readied.Status.PodIP = "10.0.1.200"
	annotated := base.DeepCopy()
	annotated.Annotations = map[string]string{"x": "y"}

	assert.True(t, podIdentityEvents.Update(updateEvent(base, relabeled)), "labels changed")
	assert.True(t, podIdentityEvents.Update(updateEvent(base, readied)), "pod IP changed")
	assert.False(t, podIdentityEvents.Update(updateEvent(base, annotated)), "nothing identity-relevant changed")
}

func updateEvent(oldPod, newPod *corev1.Pod) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}
}
