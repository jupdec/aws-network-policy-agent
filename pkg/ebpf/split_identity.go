// Package ebpf — Cilium-style identity split for NPA.
//
// Design: instead of calling LoadBpfFile for every new pod identity
// (which runs the kernel BPF verifier each time), load ONE generic TC program
// per direction at node startup and cache its FD. For each new identity:
//   1. Create inner maps (LPM trie + hash) via raw BPF syscalls — cheap.
//   2. Insert ifindex→inner_map_fd entries into the global outer HASH_OF_MAPS.
//   3. Attach the CACHED prog FD to the pod's veth — no verifier run.
//
// This reduces LoadBpfFile calls from O(identities) to O(1) per node boot.

package ebpf

import (
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Global outer map pin paths (pre-created at startup, shared across all pods)
	splitIngressMapPin   = "/sys/fs/bpf/globals/aws/maps/global_per_iface_ingress_map"
	splitCPIngressMapPin = "/sys/fs/bpf/globals/aws/maps/global_per_iface_cp_ingress_map"
	splitStateInMapPin   = "/sys/fs/bpf/globals/aws/maps/global_per_iface_state_map"
	splitEgressMapPin    = "/sys/fs/bpf/globals/aws/maps/global_per_iface_egress_map"
	splitCPEgressMapPin  = "/sys/fs/bpf/globals/aws/maps/global_per_iface_cp_egress_map"
	splitStateOutMapPin  = "/sys/fs/bpf/globals/aws/maps/global_per_iface_egress_state_map"

	// Max pods per node (outer map capacity)
	maxPodsPerNode = 512

	// BPF map type constants
	bpfMapTypeLPMTrie    = 11
	bpfMapTypeHash       = 1
	bpfMapTypeHashOfMaps = 12

	// BPF syscall commands
	bpfCmdMapCreate     = 0
	bpfCmdMapUpdateElem = 2
	bpfCmdObjPin        = 6
	bpfCmdObjGet        = 7
)

// bpfAttrMapCreate mirrors the kernel's bpf_attr for BPF_MAP_CREATE.
// Must match the kernel ABI exactly.
type bpfAttrMapCreate struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerMapFd uint32
	numaNode   uint32
	mapName    [16]byte
	mapIfindex uint32
	btfFd      uint32
	btfKeyID   uint32
	btfValID   uint32
	_          [4]byte // pad to 64 bytes
}

type bpfAttrObjPinGet struct {
	pathname uintptr
	fd       uint32
	_        [4]byte
}

type bpfAttrMapElem struct {
	mapFd uint32
	_     [4]byte
	key   uint64
	value uint64 // union: value or next_key pointer
	flags uint64
}

func bpfSyscall(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

func createBpfMap(mapType, keySize, valueSize, maxEntries, mapFlags, innerMapFd uint32, name string) (int, error) {
	attr := bpfAttrMapCreate{
		mapType:    mapType,
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
		mapFlags:   mapFlags,
		innerMapFd: innerMapFd,
	}
	if len(name) > 15 {
		name = name[:15]
	}
	copy(attr.mapName[:], name)
	fd, err := bpfSyscall(bpfCmdMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("BPF_MAP_CREATE %s: %w", name, err)
	}
	return int(fd), nil
}

func pinBpfObj(fd int, path string) error {
	bpath := append([]byte(path), 0)
	attr := bpfAttrObjPinGet{
		pathname: uintptr(unsafe.Pointer(&bpath[0])),
		fd:       uint32(fd),
	}
	if err := os.MkdirAll("/sys/fs/bpf/globals/aws/maps", 0700); err != nil {
		return err
	}
	_, err := bpfSyscall(bpfCmdObjPin, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return fmt.Errorf("BPF_OBJ_PIN %s: %w", path, err)
	}
	return nil
}

func getBpfObjFd(path string) (int, error) {
	bpath := append([]byte(path), 0)
	attr := bpfAttrObjPinGet{
		pathname: uintptr(unsafe.Pointer(&bpath[0])),
	}
	fd, err := bpfSyscall(bpfCmdObjGet, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("BPF_OBJ_GET %s: %w", path, err)
	}
	return int(fd), nil
}

func updateBpfMapElem(mapFd int, key, value unsafe.Pointer, flags uint64) error {
	attr := bpfAttrMapElem{
		mapFd: uint32(mapFd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: flags,
	}
	_, err := bpfSyscall(bpfCmdMapUpdateElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// IdentitySplitMaps holds the global outer maps and the cached generic prog FDs.
type IdentitySplitMaps struct {
	mu sync.Mutex

	// Outer HASH_OF_MAPS FDs (one per map type per direction)
	ingressOuterFD   int // ifindex → ingress LPM trie
	cpIngressOuterFD int // ifindex → cluster-policy ingress LPM trie
	stateInOuterFD   int // ifindex → ingress pod-state hash
	egressOuterFD    int // ifindex → egress LPM trie
	cpEgressOuterFD  int // ifindex → cluster-policy egress LPM trie
	stateOutOuterFD  int // ifindex → egress pod-state hash

	// Cached generic program FDs (loaded once per direction, reused for all pods)
	genericIngressProgFD int
	genericEgressProgFD  int

	initialized bool
}

var globalSplitMaps = &IdentitySplitMaps{
	genericIngressProgFD: -1,
	genericEgressProgFD:  -1,
}

// InitSplitMaps creates or reuses the six outer HASH_OF_MAPS and pins them.
// Called once at NPA startup, before any LoadBpfFile calls.
func InitSplitMaps() (*IdentitySplitMaps, error) {
	s := globalSplitMaps
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return s, nil
	}

	// Template inner maps — define the schema for inner maps we'll create per identity.
	// These FDs are only used as templates for outer map creation; they're closed after.
	lpmTemplateFD, err := createBpfMap(bpfMapTypeLPMTrie, 8, 192, 65536, 1 /*NO_PREALLOC*/, 0, "lpm_tmpl")
	if err != nil {
		return nil, fmt.Errorf("create LPM template: %w", err)
	}
	defer unix.Close(lpmTemplateFD)

	cpLpmTemplateFD, err := createBpfMap(bpfMapTypeLPMTrie, 8, 240, 65536, 1, 0, "cp_lpm_tmpl")
	if err != nil {
		return nil, fmt.Errorf("create CP LPM template: %w", err)
	}
	defer unix.Close(cpLpmTemplateFD)

	stateTemplateFD, err := createBpfMap(bpfMapTypeHash, 4, 1, 2, 1, 0, "state_tmpl")
	if err != nil {
		return nil, fmt.Errorf("create state template: %w", err)
	}
	defer unix.Close(stateTemplateFD)

	type outerSpec struct {
		pinPath    string
		tmplFD     int
		fdPtr      *int
	}
	specs := []outerSpec{
		{splitIngressMapPin, lpmTemplateFD, &s.ingressOuterFD},
		{splitCPIngressMapPin, cpLpmTemplateFD, &s.cpIngressOuterFD},
		{splitStateInMapPin, stateTemplateFD, &s.stateInOuterFD},
		{splitEgressMapPin, lpmTemplateFD, &s.egressOuterFD},
		{splitCPEgressMapPin, cpLpmTemplateFD, &s.cpEgressOuterFD},
		{splitStateOutMapPin, stateTemplateFD, &s.stateOutOuterFD},
	}

	for _, spec := range specs {
		// Reuse if already pinned (NPA restart case)
		if _, err := os.Stat(spec.pinPath); err == nil {
			fd, err := getBpfObjFd(spec.pinPath)
			if err != nil {
				return nil, fmt.Errorf("get pinned outer map %s: %w", spec.pinPath, err)
			}
			*spec.fdPtr = fd
			continue
		}
		// Create new outer map with template inner FD
		fd, err := createBpfMap(bpfMapTypeHashOfMaps, 4, 4, maxPodsPerNode, 0, uint32(spec.tmplFD), "outer_map")
		if err != nil {
			return nil, fmt.Errorf("create outer map %s: %w", spec.pinPath, err)
		}
		if err := pinBpfObj(fd, spec.pinPath); err != nil {
			unix.Close(fd)
			return nil, err
		}
		*spec.fdPtr = fd
	}

	s.initialized = true
	log().Info("Cilium-style identity split maps initialized")
	return s, nil
}

// PodIdentityMaps holds the per-identity inner map FDs created for one pod.
type PodIdentityMaps struct {
	IfIndex      uint32
	IngressFD    int // namespace-policy LPM trie
	CPIngressFD  int // cluster-policy LPM trie
	StateInFD    int // ingress pod-state hash
	EgressFD     int // namespace-policy egress LPM trie
	CPEgressFD   int // cluster-policy egress LPM trie
	StateOutFD   int // egress pod-state hash
}

// Close releases all inner map FDs (after they've been inserted into outer maps).
func (p *PodIdentityMaps) Close() {
	for _, fd := range []int{p.IngressFD, p.CPIngressFD, p.StateInFD, p.EgressFD, p.CPEgressFD, p.StateOutFD} {
		if fd > 0 {
			unix.Close(fd)
		}
	}
}

// CreateInnerMaps creates the six inner maps for a new pod identity and
// inserts them into the outer HASH_OF_MAPS keyed by ifindex.
// Called once per new unique identity arriving at a node.
func (s *IdentitySplitMaps) CreateInnerMaps(ifindex uint32, lpmValueSize, cpLpmValueSize uint32) (*PodIdentityMaps, error) {
	p := &PodIdentityMaps{IfIndex: ifindex}

	var err error
	p.IngressFD, err = createBpfMap(bpfMapTypeLPMTrie, 8, lpmValueSize, 65536, 1, 0, "in_np")
	if err != nil {
		return nil, err
	}
	p.CPIngressFD, err = createBpfMap(bpfMapTypeLPMTrie, 8, cpLpmValueSize, 65536, 1, 0, "in_cp")
	if err != nil {
		p.Close()
		return nil, err
	}
	p.StateInFD, err = createBpfMap(bpfMapTypeHash, 4, 1, 2, 1, 0, "in_st")
	if err != nil {
		p.Close()
		return nil, err
	}
	p.EgressFD, err = createBpfMap(bpfMapTypeLPMTrie, 8, lpmValueSize, 65536, 1, 0, "eg_np")
	if err != nil {
		p.Close()
		return nil, err
	}
	p.CPEgressFD, err = createBpfMap(bpfMapTypeLPMTrie, 8, cpLpmValueSize, 65536, 1, 0, "eg_cp")
	if err != nil {
		p.Close()
		return nil, err
	}
	p.StateOutFD, err = createBpfMap(bpfMapTypeHash, 4, 1, 2, 1, 0, "eg_st")
	if err != nil {
		p.Close()
		return nil, err
	}

	// Insert into outer maps
	type binding struct {
		outerFD int
		innerFD int
	}
	bindings := []binding{
		{s.ingressOuterFD, p.IngressFD},
		{s.cpIngressOuterFD, p.CPIngressFD},
		{s.stateInOuterFD, p.StateInFD},
		{s.egressOuterFD, p.EgressFD},
		{s.cpEgressOuterFD, p.CPEgressFD},
		{s.stateOutOuterFD, p.StateOutFD},
	}
	for _, b := range bindings {
		innerFDu32 := uint32(b.innerFD)
		if err := updateBpfMapElem(b.outerFD,
			unsafe.Pointer(&ifindex),
			unsafe.Pointer(&innerFDu32),
			0); err != nil {
			p.Close()
			return nil, fmt.Errorf("update outer map ifindex %d: %w", ifindex, err)
		}
	}

	log().Infof("Cilium split: created inner maps for ifindex %d", ifindex)
	return p, nil
}

// SetGenericIngressProgFD caches the prog FD loaded for the first identity.
func (s *IdentitySplitMaps) SetGenericIngressProgFD(fd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.genericIngressProgFD < 0 {
		s.genericIngressProgFD = fd
	}
}

// SetGenericEgressProgFD caches the prog FD loaded for the first identity.
func (s *IdentitySplitMaps) SetGenericEgressProgFD(fd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.genericEgressProgFD < 0 {
		s.genericEgressProgFD = fd
	}
}

// GetGenericProgFDs returns the cached prog FDs. Returns -1 if not yet loaded.
func (s *IdentitySplitMaps) GetGenericProgFDs() (ingressFD, egressFD int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.genericIngressProgFD, s.genericEgressProgFD
}
