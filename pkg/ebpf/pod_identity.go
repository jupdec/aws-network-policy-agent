package ebpf

import (
	"errors"
	"fmt"
	"sort"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

// Moving a pod between identifiers. A pod's identifier follows its labels, so it changes
// when the labels change, when they become readable after the pod started under an
// isolated identifier, and once on upgrade from name-prefix identifiers. The new
// identifier's maps are programmed before the pod is moved, and the move replaces the
// pod's TC filters in place, so the pod is filtered throughout: first by the old rules,
// then by the new.

// tcHook is the clsact hook a filter hangs off. The pod's ingress program runs on the
// host veth's egress hook and its egress program on the ingress hook, as in
// attachIngressBPFProbe and attachEgressBPFProbe.
type tcHook uint32

const (
	tcHookIngress = tcHook(netlink.HANDLE_MIN_INGRESS)
	tcHookEgress  = tcHook(netlink.HANDLE_MIN_EGRESS)
)

// tcFilterReplacer replaces the BPF filter on hostVethName's hook with progFD.
type tcFilterReplacer interface {
	ReplaceFilter(hostVethName string, hook tcHook, progFD int, funcName string) error
}

// netlinkFilterReplacer uses the same filter attributes as aws-ebpf-sdk-go's attach
// (handle, priority, protocol), so RTM_NEWTFILTER with NLM_F_REPLACE swaps the program
// of the existing filter instead of adding a second one.
type netlinkFilterReplacer struct{}

func (netlinkFilterReplacer) ReplaceFilter(hostVethName string, hook tcHook, progFD int, funcName string) error {
	link, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return fmt.Errorf("find link %s: %w", hostVethName, err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    uint32(hook),
			Handle:    constdef.DEFAULT_BPF_FILTER_HANDLE,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         funcName,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replace filter on %s: %w", hostVethName, err)
	}
	return nil
}

func (l *bpfClient) filterReplacer() tcFilterReplacer {
	if l.tcReplacer != nil {
		return l.tcReplacer
	}
	return netlinkFilterReplacer{}
}

func (l *bpfClient) AttachedPodIdentifier(pod types.NamespacedName) (string, bool) {
	value, ok := l.podToIdentifier.Load(utils.GetPodNamespacedName(pod.Name, pod.Namespace))
	if !ok {
		return "", false
	}
	return value.(string), true
}

func (l *bpfClient) LoadBPFPrograms(podIdentifier string) (bool, error) {
	l.podIdentifierLocks.Lock(podIdentifier)
	defer l.podIdentifierLocks.Unlock(podIdentifier)

	loaded := l.isFirstPodInPodIdentifierLocked(podIdentifier)
	if _, err := l.ingressProgram(podIdentifier); err != nil {
		return loaded, fmt.Errorf("load ingress program for %s: %w", podIdentifier, err)
	}
	if _, err := l.egressProgram(podIdentifier); err != nil {
		return loaded, fmt.Errorf("load egress program for %s: %w", podIdentifier, err)
	}
	return loaded, nil
}

// lockPair locks two identifiers in a fixed order so two concurrent moves in opposite
// directions cannot deadlock. It returns the matching unlock.
func (l *bpfClient) lockPair(a, b string) func() {
	keys := []string{a, b}
	sort.Strings(keys)
	l.podIdentifierLocks.Lock(keys[0])
	l.podIdentifierLocks.Lock(keys[1])
	return func() {
		l.podIdentifierLocks.Unlock(keys[1])
		l.podIdentifierLocks.Unlock(keys[0])
	}
}

func (l *bpfClient) RepointBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	oldIdentifier, attached := l.AttachedPodIdentifier(pod)
	if !attached {
		return l.adoptPod(pod, podIdentifier, numInterfaces)
	}
	if oldIdentifier == podIdentifier {
		return nil
	}

	unlock := l.lockPair(oldIdentifier, podIdentifier)
	defer unlock()

	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	// Re-check under the locks: a CNI DEL or another move may have run in between.
	if current, ok := l.AttachedPodIdentifier(pod); !ok || current != oldIdentifier {
		return fmt.Errorf("pod %s moved off %s while waiting for the lock", pod, oldIdentifier)
	}

	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		return fmt.Errorf("programs for %s are not loaded", podIdentifier)
	}
	newContext := value.(BPFContext)
	newIngressFD, newEgressFD := newContext.ingressPgmInfo.Program.ProgFD, newContext.egressPgmInfo.Program.ProgFD
	if newIngressFD == 0 || newEgressFD == 0 {
		return fmt.Errorf("programs for %s are not loaded", podIdentifier)
	}

	interfaceCount, err := l.getInterfaceCountForPod(pod, podIdentifier, numInterfaces)
	if err != nil {
		return err
	}

	oldIngressFD, _ := l.ingressPodToProgMap.Load(podNamespacedName)
	oldEgressFD, _ := l.egressPodToProgMap.Load(podNamespacedName)
	replacer := l.filterReplacer()

	// Replace every interface, and on failure put the ones already moved back, so the pod
	// never runs under a mix of two identifiers' rules.
	var moved []string
	rollback := func() {
		for _, hostVethName := range moved {
			if fd, ok := oldIngressFD.(int); ok {
				_ = replacer.ReplaceFilter(hostVethName, tcHookEgress, fd, utils.TC_INGRESS_PROG)
			}
			if fd, ok := oldEgressFD.(int); ok {
				_ = replacer.ReplaceFilter(hostVethName, tcHookIngress, fd, utils.TC_EGRESS_PROG)
			}
		}
	}
	for index := 0; index < interfaceCount; index++ {
		hostVethName, err := utils.GetHostVethName(pod.Name, pod.Namespace, index, []string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})
		if err != nil {
			rollback()
			return fmt.Errorf("host veth for pod %s interface %d: %w", pod, index, err)
		}
		if err := replacer.ReplaceFilter(hostVethName, tcHookEgress, newIngressFD, utils.TC_INGRESS_PROG); err != nil {
			rollback()
			return fmt.Errorf("move ingress filter of pod %s to %s: %w", pod, podIdentifier, err)
		}
		moved = append(moved, hostVethName)
		if err := replacer.ReplaceFilter(hostVethName, tcHookIngress, newEgressFD, utils.TC_EGRESS_PROG); err != nil {
			rollback()
			return fmt.Errorf("move egress filter of pod %s to %s: %w", pod, podIdentifier, err)
		}
	}
	log().Infof("Moved pod %s from podIdentifier %s to %s", pod, oldIdentifier, podIdentifier)

	l.deletePodFromIngressProgPodCaches(pod.Name, pod.Namespace)
	l.deletePodFromEgressProgPodCaches(pod.Name, pod.Namespace)
	l.ingressPodToProgMap.Store(podNamespacedName, newIngressFD)
	ingressPods, _ := l.ingressProgToPodsMap.LoadOrStore(newIngressFD, make(map[string]struct{}))
	ingressPods.(map[string]struct{})[podNamespacedName] = struct{}{}
	l.egressPodToProgMap.Store(podNamespacedName, newEgressFD)
	egressPods, _ := l.egressProgToPodsMap.LoadOrStore(newEgressFD, make(map[string]struct{}))
	egressPods.(map[string]struct{})[podNamespacedName] = struct{}{}
	l.podToIdentifier.Store(podNamespacedName, podIdentifier)

	if !l.identifierInUseLocked(oldIdentifier) {
		log().Infof("No pod uses podIdentifier %s anymore, deleting its programs and maps", oldIdentifier)
		if err := l.deleteBPFProbes(oldIdentifier); err != nil {
			return errors.Join(err, fmt.Errorf("delete programs of %s", oldIdentifier))
		}
	}
	return nil
}

// adoptPod points a pod the client has no record of at podIdentifier's programs. That is a
// pod whose filters survived an agent restart (the client does not persist which pod uses
// which program) or one that was never attached. A replace creates the filter when it is
// missing and swaps the program in place otherwise, so a pod that is still filtered by
// programs from before the restart -- possibly name-prefix ones from before an upgrade --
// stays filtered throughout. If the replace fails, typically because the clsact qdisc does
// not exist yet, the regular attach creates it.
func (l *bpfClient) adoptPod(pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	if _, deleted := l.deletedPods.Load(podNamespacedName); deleted {
		return nil
	}
	l.podIdentifierLocks.Lock(podIdentifier)
	adopted, err := l.adoptPodLocked(pod, podIdentifier, numInterfaces)
	l.podIdentifierLocks.Unlock(podIdentifier)
	if err != nil {
		return err
	}
	if !adopted {
		// podConfirmedLive=false: the caller read the pod from the API, which can lag a CNI DEL.
		_, err := l.AttacheBPFProbes(pod, podIdentifier, numInterfaces, false)
		return err
	}
	return nil
}

// adoptPodLocked returns false, with no error, when the caller should fall back to a
// regular attach. Callers must hold the identifier lock.
func (l *bpfClient) adoptPodLocked(pod types.NamespacedName, podIdentifier string, numInterfaces int) (bool, error) {
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	if _, deleted := l.deletedPods.Load(podNamespacedName); deleted {
		return true, nil
	}
	if _, attached := l.AttachedPodIdentifier(pod); attached {
		// Attached while waiting for the lock, e.g. by a CNI ADD.
		return true, nil
	}
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		return false, nil
	}
	peBPFContext := value.(BPFContext)
	ingressFD, egressFD := peBPFContext.ingressPgmInfo.Program.ProgFD, peBPFContext.egressPgmInfo.Program.ProgFD
	if ingressFD == 0 || egressFD == 0 {
		return false, nil
	}
	interfaceCount, err := l.getInterfaceCountForPod(pod, podIdentifier, numInterfaces)
	if err != nil {
		return false, err
	}
	replacer := l.filterReplacer()
	for index := 0; index < interfaceCount; index++ {
		hostVethName, err := utils.GetHostVethName(pod.Name, pod.Namespace, index, []string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})
		if err != nil {
			return false, fmt.Errorf("host veth for pod %s interface %d: %w", pod, index, err)
		}
		if err := replacer.ReplaceFilter(hostVethName, tcHookEgress, ingressFD, utils.TC_INGRESS_PROG); err != nil {
			if index == 0 {
				log().Infof("Could not adopt pod %s in place (%v), attaching", pod, err)
				return false, nil
			}
			return false, fmt.Errorf("adopt ingress filter of pod %s interface %d: %w", pod, index, err)
		}
		if err := replacer.ReplaceFilter(hostVethName, tcHookIngress, egressFD, utils.TC_EGRESS_PROG); err != nil {
			return false, fmt.Errorf("adopt egress filter of pod %s interface %d: %w", pod, index, err)
		}
	}
	l.ingressPodToProgMap.Store(podNamespacedName, ingressFD)
	ingressPods, _ := l.ingressProgToPodsMap.LoadOrStore(ingressFD, make(map[string]struct{}))
	ingressPods.(map[string]struct{})[podNamespacedName] = struct{}{}
	l.egressPodToProgMap.Store(podNamespacedName, egressFD)
	egressPods, _ := l.egressProgToPodsMap.LoadOrStore(egressFD, make(map[string]struct{}))
	egressPods.(map[string]struct{})[podNamespacedName] = struct{}{}
	l.podToIdentifier.Store(podNamespacedName, podIdentifier)
	log().Infof("Adopted pod %s onto podIdentifier %s", pod, podIdentifier)
	return true, nil
}

// identifierInUseLocked reports whether an attached pod's filters point at one of the
// identifier's programs. Callers must hold the identifier lock.
func (l *bpfClient) identifierInUseLocked(podIdentifier string) bool {
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		return false
	}
	peBPFContext := value.(BPFContext)
	for _, use := range []struct {
		progFD int
		pods   interface{ Load(any) (any, bool) }
	}{
		{peBPFContext.ingressPgmInfo.Program.ProgFD, l.ingressProgToPodsMap},
		{peBPFContext.egressPgmInfo.Program.ProgFD, l.egressProgToPodsMap},
	} {
		if use.progFD == 0 {
			continue
		}
		if podSet, ok := use.pods.Load(use.progFD); ok && len(podSet.(map[string]struct{})) > 0 {
			return true
		}
	}
	return false
}

func (l *bpfClient) ReleaseUnusedPodIdentifiers(keep map[string]bool) []string {
	var candidates []string
	l.policyEndpointeBPFContext.Range(func(key, _ any) bool {
		if podIdentifier := key.(string); !keep[podIdentifier] {
			candidates = append(candidates, podIdentifier)
		}
		return true
	})
	var released []string
	for _, podIdentifier := range candidates {
		l.podIdentifierLocks.Lock(podIdentifier)
		if !l.identifierInUseLocked(podIdentifier) {
			if err := l.deleteBPFProbes(podIdentifier); err != nil {
				log().Errorf("Failed to release unused podIdentifier %s: %v", podIdentifier, err)
			} else {
				released = append(released, podIdentifier)
			}
		}
		l.podIdentifierLocks.Unlock(podIdentifier)
	}
	return released
}
