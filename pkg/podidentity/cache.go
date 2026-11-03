package podidentity

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-network-policy-agent/pkg/logger"
)

func log() logger.Logger {
	return logger.Get()
}

// NodeNameField is the pod field the informer is scoped by.
const NodeNameField = "spec.nodeName"

// PodCacheByObject scopes the manager's Pod informer to this node's pods and trims each
// cached pod to the fields identity resolution reads. Without the scope, the first Pod Get
// or Watch would start a cluster-wide pod watch on every node.
func PodCacheByObject(nodeName string) map[client.Object]cache.ByObject {
	return map[client.Object]cache.ByObject{
		&corev1.Pod{}: {
			Field:     fields.OneTermEqualSelector(NodeNameField, nodeName),
			Transform: TrimPod,
		},
	}
}

// TrimPod keeps only what the agent reads from a pod: identity (name, namespace, UID,
// labels), lifecycle (resourceVersion, deletionTimestamp), placement (nodeName,
// hostNetwork) and addressing (podIP, podIPs, phase). Everything else -- annotations,
// managed fields, container specs -- is dropped to keep the per-node cache small.
func TrimPod(obj interface{}) (interface{}, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// Tombstones (cache.DeletedFinalStateUnknown) and other types pass through.
		return obj, nil
	}
	return &corev1.Pod{
		TypeMeta: pod.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:              pod.Name,
			Namespace:         pod.Namespace,
			UID:               pod.UID,
			Labels:            pod.Labels,
			ResourceVersion:   pod.ResourceVersion,
			DeletionTimestamp: pod.DeletionTimestamp,
		},
		Spec: corev1.PodSpec{
			NodeName:    pod.Spec.NodeName,
			HostNetwork: pod.Spec.HostNetwork,
		},
		Status: corev1.PodStatus{
			Phase:  pod.Status.Phase,
			PodIP:  pod.Status.PodIP,
			PodIPs: pod.Status.PodIPs,
		},
	}, nil
}
