package podidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func newPod(name string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod", Labels: podLabels, UID: types.UID(name + "-uid")},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.5"},
	}
}

func newFakeReader(objs ...client.Object) client.Reader {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func failingReader(t *testing.T) client.Reader {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("apiserver unreachable")
		},
	}).Build()
}

var dbKey = types.NamespacedName{Name: "db-0", Namespace: "prod"}

func TestResolve_IdentityComesFromLabelsNotName(t *testing.T) {
	r := NewAPIResolver(nil, newFakeReader(newPod("db-0", map[string]string{"app": "db"}),
		newPod("db-evil", map[string]string{"app": "evil"})))

	db, err := r.Resolve(context.Background(), dbKey)
	require.NoError(t, err)
	evil, err := r.Resolve(context.Background(), types.NamespacedName{Name: "db-evil", Namespace: "prod"})
	require.NoError(t, err)

	assert.Equal(t, utils.PodIdentity(map[string]string{"app": "db"}, "prod"), db.Identity)
	assert.NotEqual(t, db.Identity, evil.Identity, "colliding names must not share an identity")
	assert.Equal(t, "10.0.0.5", db.PodIP)
}

func TestResolve_UsesCacheOnlyOnceReady(t *testing.T) {
	cache := newFakeReader(newPod("db-0", map[string]string{"app": "cached"}))
	live := newFakeReader(newPod("db-0", map[string]string{"app": "live"}))
	r := NewAPIResolver(cache, live)

	res, err := r.Resolve(context.Background(), dbKey)
	require.NoError(t, err)
	assert.Equal(t, "live", res.Labels["app"], "cache must not be read before it has synced")

	r.MarkCacheReady()
	res, err = r.Resolve(context.Background(), dbKey)
	require.NoError(t, err)
	assert.Equal(t, "cached", res.Labels["app"])
}

func TestResolve_CacheMissFallsBackToLive(t *testing.T) {
	r := NewAPIResolver(newFakeReader(), newFakeReader(newPod("db-0", map[string]string{"app": "db"})))
	r.MarkCacheReady()

	res, err := r.Resolve(context.Background(), dbKey)
	require.NoError(t, err, "a just-created pod may not be in the informer yet")
	assert.Equal(t, "db", res.Labels["app"])
}

func TestResolve_Errors(t *testing.T) {
	r := NewAPIResolver(nil, newFakeReader())
	_, err := r.Resolve(context.Background(), dbKey)
	assert.ErrorIs(t, err, ErrPodNotFound)

	r = NewAPIResolver(nil, failingReader(t))
	_, err = r.Resolve(context.Background(), dbKey)
	assert.ErrorIs(t, err, ErrUnavailable)

	_, err = Unconfigured{}.Resolve(context.Background(), dbKey)
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestResolveCached_NeverReadsLive(t *testing.T) {
	r := NewAPIResolver(newFakeReader(), newFakeReader(newPod("db-0", nil)))
	_, err := r.ResolveCached(context.Background(), dbKey)
	assert.ErrorIs(t, err, ErrUnavailable, "cache not ready")

	r.MarkCacheReady()
	_, err = r.ResolveCached(context.Background(), dbKey)
	assert.ErrorIs(t, err, ErrPodNotFound)
}

func TestFromPod_NilLabels(t *testing.T) {
	res := FromPod(newPod("db-0", nil))
	assert.NotNil(t, res.Labels)
	assert.Equal(t, utils.PodIdentity(map[string]string{}, "prod"), res.Identity)
}

func TestTrimPod(t *testing.T) {
	pod := newPod("db-0", map[string]string{"app": "db"})
	pod.Annotations = map[string]string{"big": "blob"}
	pod.Spec.Containers = []corev1.Container{{Name: "c"}}
	pod.Spec.HostNetwork = true

	out, err := TrimPod(pod)
	require.NoError(t, err)
	trimmed := out.(*corev1.Pod)
	assert.Nil(t, trimmed.Annotations)
	assert.Nil(t, trimmed.Spec.Containers)
	assert.Equal(t, pod.Labels, trimmed.Labels)
	assert.Equal(t, pod.UID, trimmed.UID)
	assert.True(t, trimmed.Spec.HostNetwork)
	assert.Equal(t, "node-1", trimmed.Spec.NodeName)
	assert.Equal(t, "10.0.0.5", trimmed.Status.PodIP)

	passthrough, err := TrimPod("not a pod")
	require.NoError(t, err)
	assert.Equal(t, "not a pod", passthrough)
}

func TestPodCacheByObject_ScopesToNode(t *testing.T) {
	byObject := PodCacheByObject("node-1")
	require.Len(t, byObject, 1)
	for obj, opts := range byObject {
		_, isPod := obj.(*corev1.Pod)
		assert.True(t, isPod)
		assert.Equal(t, "spec.nodeName=node-1", opts.Field.String())
		assert.NotNil(t, opts.Transform)
	}
}
