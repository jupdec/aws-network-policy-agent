// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rpc

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRunRPCHandler_NoExistingSocket(t *testing.T) {
	testSocketPath := "/tmp/test-rpc-handler.sock"
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestRunRPCHandler_StaleSocketCleanup(t *testing.T) {
	testSocketPath := "/tmp/temp-rpc-handler.sock"

	// Create a stale socket file
	file, err := os.Create(testSocketPath)
	if err != nil {
		t.Fatalf("Failed to create stale socket file: %v", err)
	}
	file.Close()
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestEnforceNpToPod_AttachesAsConfirmedLive(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// A CNI ADD proves the pod exists, so its attach must clear any stale
	// deleted-pod marker under the identifier lock instead of being skipped.
	assert.Equal(t, "AttacheBPFProbes", mockBpfClient.CallLog[0])
	assert.True(t, mockBpfClient.LastAttachPodConfirmedLive)
}

func TestEnforceNpToPod_NilClusterPolicyReconciler_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_NilClusterPolicyEBPFClient_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	// clusterReconciler with nil eBPF client
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", nil)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_OneReconcilerReady_ReturnsError(t *testing.T) {
	// Reverse case: clusterPolicyReconciler is ready but policyReconciler is nil
	mockBpfClient := &ebpf.MockBpfClient{}
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, err.Error(), "One of the policy reconcilers is not ready")
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_BothReconcilersNil_ReturnsSuccess(t *testing.T) {
	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestEnforceNpToPod_NoPolicies_UpdatesBothPodStateMaps(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// With no policies and AttacheBPFProbes reporting no first pod,
	// the "no active policies" branch fires and calls UpdatePodStateEbpfMaps twice:
	// once for POD_STATE_MAP_KEY and once for CLUSTER_POLICY_POD_STATE_MAP_KEY
	updateCount := 0
	for _, call := range mockBpfClient.CallLog {
		if call == "UpdatePodStateEbpfMaps" {
			updateCount++
		}
	}
	assert.Equal(t, 2, updateCount, "should update both pod state map and cluster policy pod state map")
}

// TestEnforceNpToPod_FailsClosedOnPodStateError verifies that EnforceNpToPod
// returns an error rather than a success reply when the pod-state map write
// fails on the no-cached-policies path that seeds default-allow/default-deny.
// Both reconcilers are wired so the readiness check passes and execution
// reaches UpdatePodStateEbpfMaps.
func TestEnforceNpToPod_FailsClosedOnPodStateError(t *testing.T) {
	injected := errors.New("simulated pod state write failure")
	mockBpfClient := &ebpf.MockBpfClient{
		UpdatePodStateEbpfMapsErr: injected,
	}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})

	assert.ErrorIs(t, err, injected)
	assert.Nil(t, resp, "rpc must not return a success reply when the pod-state write fails")
}

// Pods the API server knows in these tests. nginx-old123 and nginx-new456 are replicas
// (identical labels); db-0 and db-evil share a name prefix but not labels.
var (
	nginxLabels    = map[string]string{"app": "nginx"}
	nginxIdentity  = utils.PodIdentity(nginxLabels, "default")
	testPodsByName = map[string]map[string]string{
		"nginx-old123": nginxLabels,
		"nginx-new456": nginxLabels,
		"db-0":         {"app": "db"},
		"db-evil":      {"app": "evil"},
	}
)

// testResolver resolves the pods in testPodsByName through the production resolver, reading
// a fake API server.
func testResolver(t *testing.T) *podidentity.APIResolver {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for name, podLabels := range testPodsByName {
		builder = builder.WithObjects(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: podLabels},
			Status:     corev1.PodStatus{PodIP: "10.0.0.9"},
		})
	}
	return podidentity.NewAPIResolver(nil, builder.Build())
}

func policyEndpointSelecting(name string, selector map[string]string, pods ...string) *policyk8sawsv1.PolicyEndpoint {
	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-abcde", Namespace: "default"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{MatchLabels: selector},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: name, Namespace: "default"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress:       []policyk8sawsv1.EndpointInfo{{CIDR: "10.1.0.0/16"}},
		},
	}
	for _, pod := range pods {
		pe.Spec.PodSelectorEndpoints = append(pe.Spec.PodSelectorEndpoints,
			policyk8sawsv1.PodEndpoint{Name: pod, Namespace: "default", PodIP: "10.0.0.5", HostIP: "10.0.0.1"})
	}
	return pe
}

// reconcilerWithCachedPolicy returns a PolicyEndpoints reconciler whose local cache knows an
// egress policy for the nginx identity in "default", populated the same way production does
// it: by reconciling a PolicyEndpoint that selects a pod of that identity on this node.
func reconcilerWithCachedPolicy(t *testing.T, ebpfClient *ebpf.MockBpfClient) *controllers.PolicyEndpointsReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	pe := policyEndpointSelecting("np-x", nginxLabels, "nginx-old123")
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pe).Build()
	reconciler := controllers.NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", ebpfClient, false)
	reconciler.SetIdentityResolver(testResolver(t))
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace}})
	require.NoError(t, err)
	assert.True(t, reconciler.ArePoliciesAvailableInLocalCache(nginxIdentity), "precondition: policy cached")
	return reconciler
}

// When AttacheBPFProbes reports the first pod of the identifier, the CNI ADD
// programs its freshly loaded maps and marks the pod POLICIES_APPLIED; later
// pods share maps that are already programmed.
func TestEnforceNpToPod_CachedPolicies_ProgramsMapsOnlyForFirstPod(t *testing.T) {
	for _, tt := range []struct {
		name        string
		firstPod    bool
		wantProgram bool
	}{
		{name: "first pod of the identifier", firstPod: true, wantProgram: true},
		{name: "later pod of the identifier", firstPod: false, wantProgram: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mockBpfClient := &ebpf.MockBpfClient{}
			reconciler := reconcilerWithCachedPolicy(t, mockBpfClient)
			mockBpfClient.Reset()
			mockBpfClient.AttachFirstPodInPodIdentifier = tt.firstPod
			s := &server{
				policyReconciler:        reconciler,
				clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient),
			}

			resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
				K8S_POD_NAME:        "nginx-new456",
				K8S_POD_NAMESPACE:   "default",
				NETWORK_POLICY_MODE: "standard",
				InterfaceCount:      1,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.Success)
			attached, _ := mockBpfClient.AttachedPodIdentifier(types.NamespacedName{Name: "nginx-new456", Namespace: "default"})
			assert.Equal(t, nginxIdentity, attached, "a replica joins its siblings' identity through its labels")

			if !tt.wantProgram {
				assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
				assert.Empty(t, mockBpfClient.PodStateByIdentifier)
				return
			}
			assert.Contains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
			assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: "10.1.0.0/16"}}, mockBpfClient.LastEgressRules)
			assert.Equal(t, map[ebpf.PodStateKey]int{
				{PodIdentifier: nginxIdentity, MapKey: ebpf.POD_STATE_MAP_KEY}:                ebpf.POLICIES_APPLIED,
				{PodIdentifier: nginxIdentity, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}: ebpf.DEFAULT_ALLOW,
			}, mockBpfClient.PodStateByIdentifier)
		})
	}
}

// Only a cluster policy selects the pod: the ADD must still program the cluster
// policy maps and mark the cluster-policy key POLICIES_APPLIED, while the
// namespaced-policy key goes to the mode default.
func TestEnforceNpToPod_CachedClusterPolicyOnly_ProgramsClusterPolicyMaps(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-x-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-x"},
			Tier:      policyk8sawsv1.AdminTier,
			PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{
				{Name: "nginx-old123", Namespace: "default", PodIP: "10.0.0.5", HostIP: "10.0.0.1"},
			},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.1.0.0/16", Action: "Deny"}},
		},
	}
	mockBpfClient := &ebpf.MockBpfClient{}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cpe).Build()
	resolver := testResolver(t)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(k8sClient, "10.0.0.1", mockBpfClient)
	clusterReconciler.SetIdentityResolver(resolver)
	_, err := clusterReconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cpe.Name}})
	require.NoError(t, err)
	require.True(t, clusterReconciler.ArePoliciesAvailableInLocalCache(nginxIdentity), "precondition: cluster policy cached")

	mockBpfClient.Reset()
	mockBpfClient.AttachFirstPodInPodIdentifier = true
	policyReconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	policyReconciler.SetIdentityResolver(resolver)
	s := &server{
		policyReconciler:        policyReconciler,
		clusterPolicyReconciler: clusterReconciler,
	}
	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-new456",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
	assert.Contains(t, mockBpfClient.CallLog, "UpdateClusterPolicyEbpfMaps")
	assert.Equal(t, map[ebpf.PodStateKey]int{
		{PodIdentifier: nginxIdentity, MapKey: ebpf.POD_STATE_MAP_KEY}:                ebpf.DEFAULT_ALLOW,
		{PodIdentifier: nginxIdentity, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}: ebpf.POLICIES_APPLIED,
	}, mockBpfClient.PodStateByIdentifier)
}

// The Robosec repro at pod start: db-evil's name reduces to db's prefix, but its labels
// differ, so it neither joins db-0's identity nor gets db-policy's allow. It lands in the
// mode default, under default-deny's ingress isolation once that is reconciled.
func TestEnforceNpToPod_CollidingNameDoesNotInheritPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	dbPolicy := policyEndpointSelecting("db-policy", map[string]string{"app": "db"}, "db-0")
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dbPolicy).Build()
	mockBpfClient := &ebpf.MockBpfClient{AttachFirstPodInPodIdentifier: true}
	reconciler := controllers.NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", mockBpfClient, false)
	reconciler.SetIdentityResolver(testResolver(t))
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: dbPolicy.Name, Namespace: "default"}})
	require.NoError(t, err)
	dbIdentity := utils.PodIdentity(map[string]string{"app": "db"}, "default")
	require.True(t, reconciler.ArePoliciesAvailableInLocalCache(dbIdentity))
	mockBpfClient.Reset()

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient),
	}
	_, err = s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME: "db-evil", K8S_POD_NAMESPACE: "default", NETWORK_POLICY_MODE: "standard", InterfaceCount: 1,
	})
	require.NoError(t, err)

	evilIdentity := utils.PodIdentity(map[string]string{"app": "evil"}, "default")
	attached, _ := mockBpfClient.AttachedPodIdentifier(types.NamespacedName{Name: "db-evil", Namespace: "default"})
	assert.Equal(t, evilIdentity, attached)
	assert.NotEqual(t, dbIdentity, attached)
	assert.False(t, reconciler.ArePoliciesAvailableInLocalCache(evilIdentity), "db-policy must not bind db-evil")
	assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps")
	assert.Equal(t, ebpf.DEFAULT_ALLOW, mockBpfClient.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: evilIdentity, MapKey: ebpf.POD_STATE_MAP_KEY}])
	assert.NotContains(t, mockBpfClient.PodStateByIdentifier, ebpf.PodStateKey{PodIdentifier: dbIdentity, MapKey: ebpf.POD_STATE_MAP_KEY})
}

// The fast path: the first pod of a label set on the node gets the rules of the policies
// whose selector matches it before NPC lists it (#691).
func TestEnforceNpToPod_SelectorFastPathBeforePolicyEndpointListsPod(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	// NPC has not listed nginx-new456 (or any nginx pod on this node) yet.
	pe := policyEndpointSelecting("np-x", nginxLabels)
	other := policyEndpointSelecting("np-other", map[string]string{"app": "db"})
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pe, other).Build()
	mockBpfClient := &ebpf.MockBpfClient{AttachFirstPodInPodIdentifier: true}
	reconciler := controllers.NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", mockBpfClient, false)
	reconciler.SetIdentityResolver(testResolver(t))
	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient),
	}

	_, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME: "nginx-new456", K8S_POD_NAMESPACE: "default", NETWORK_POLICY_MODE: "strict", InterfaceCount: 1,
	})
	require.NoError(t, err)

	assert.True(t, reconciler.ArePoliciesAvailableInLocalCache(nginxIdentity), "selector match binds the identity")
	assert.Equal(t, []fwrp.EbpfFirewallRules{{IPCidr: "10.1.0.0/16"}}, mockBpfClient.EgressByIdentifier[nginxIdentity])
	assert.Equal(t, ebpf.POLICIES_APPLIED,
		mockBpfClient.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: nginxIdentity, MapKey: ebpf.POD_STATE_MAP_KEY}])
}

// Labels that cannot be read never fall back to the name: the pod gets an identity of its
// own in the mode default.
func TestEnforceNpToPod_UnresolvableLabelsGetIsolatedIdentity(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{AttachFirstPodInPodIdentifier: true}
	reconciler := reconcilerWithCachedPolicy(t, mockBpfClient)
	mockBpfClient.Reset()
	reconciler.SetIdentityResolver(podidentity.Unconfigured{})
	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient),
	}

	_, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME: "nginx-new456", K8S_POD_NAMESPACE: "default", NETWORK_POLICY_MODE: "strict", InterfaceCount: 1,
	})
	require.NoError(t, err)

	isolated := utils.IsolatedPodIdentity("nginx-new456", "default")
	attached, _ := mockBpfClient.AttachedPodIdentifier(types.NamespacedName{Name: "nginx-new456", Namespace: "default"})
	assert.Equal(t, isolated, attached)
	assert.NotContains(t, mockBpfClient.CallLog, "UpdateEbpfMaps", "the nginx policy must not be applied on a name match")
	assert.Equal(t, ebpf.DEFAULT_DENY,
		mockBpfClient.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: isolated, MapKey: ebpf.POD_STATE_MAP_KEY}])
}

// CNI DEL releases the pod from the identifier it is attached to, without its labels.
func TestDeletePodNp_ReleasesAttachedIdentifier(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	pod := types.NamespacedName{Name: "gone", Namespace: "default"}
	_, err := mockBpfClient.AttacheBPFProbes(pod, "abc@default", 1, true)
	require.NoError(t, err)
	s := &server{policyReconciler: reconciler}

	resp, err := s.DeletePodNp(context.Background(), &rpc.DeleteNpRequest{K8S_POD_NAME: "gone", K8S_POD_NAMESPACE: "default"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	_, attached := mockBpfClient.AttachedPodIdentifier(pod)
	assert.False(t, attached)
}
