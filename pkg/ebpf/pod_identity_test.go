package ebpf

import (
	"errors"
	"os"
	"syscall"
	"testing"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

type replaceCall struct {
	hostVeth string
	hook     tcHook
	progFD   int
}

type fakeReplacer struct {
	calls []replaceCall
	// failAt fails the call with this index (0-based); -1 never fails.
	failAt int
}

func (f *fakeReplacer) ReplaceFilter(hostVethName string, hook tcHook, progFD int, _ string) error {
	f.calls = append(f.calls, replaceCall{hostVethName, hook, progFD})
	if len(f.calls)-1 == f.failAt {
		return errors.New("netlink: operation not permitted")
	}
	return nil
}

// newRepointTestClient returns a client whose program loads hand out disposable real FDs
// (so teardown closes descriptors the test owns) and whose TC attaches succeed.
func newRepointTestClient(t *testing.T) (*bpfClient, *fakeReplacer) {
	t.Helper()
	client, _ := newRaceTestBpfClient(t)
	client.ingressBinary, client.egressBinary = "ingress.bpf.o", "egress.bpf.o"
	ctrl := gomock.NewController(t)

	var mapIDs uint32
	nextMap := func() goebpfmaps.BpfMap { mapIDs++; return goebpfmaps.BpfMap{MapID: mapIDs} }
	sdk := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	sdk.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(file, podIdentifier string) (map[string]goelf.BpfData, map[string]goebpfmaps.BpfMap, error) {
			fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				return nil, nil, err
			}
			t.Cleanup(func() { _ = syscall.Close(fd) })
			direction, maps := "ingress", map[string]goebpfmaps.BpfMap{
				utils.TC_INGRESS_MAP: nextMap(), utils.TC_CLUSTER_POLICY_INGRESS_MAP: nextMap(), utils.TC_INGRESS_POD_STATE_MAP: nextMap(),
			}
			if file == client.egressBinary {
				direction, maps = "egress", map[string]goebpfmaps.BpfMap{
					utils.TC_EGRESS_MAP: nextMap(), utils.TC_CLUSTER_POLICY_EGRESS_MAP: nextMap(), utils.TC_EGRESS_POD_STATE_MAP: nextMap(),
				}
			}
			pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
			return map[string]goelf.BpfData{pinPath: {Program: goebpfprogs.BpfProgram{ProgFD: fd}, Maps: maps}}, nil, nil
		})
	tcClient := mock_tc.NewMockBpfTc(ctrl)
	tcClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	tcClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	client.bpfSDKClient = sdk
	client.bpfTCClient = tcClient

	replacer := &fakeReplacer{failAt: -1}
	client.tcReplacer = replacer

	origGetHostVethName := utils.GetHostVethName
	t.Cleanup(func() { utils.GetHostVethName = origGetHostVethName })
	utils.GetHostVethName = func(name, _ string, index int, _ []string) (string, error) {
		return "eni" + name + string(rune('0'+index)), nil
	}
	return client, replacer
}

func progFDs(t *testing.T, client *bpfClient, podIdentifier string) (int, int) {
	t.Helper()
	value, ok := client.policyEndpointeBPFContext.Load(podIdentifier)
	require.True(t, ok, "no context for %s", podIdentifier)
	ctx := value.(BPFContext)
	return ctx.ingressPgmInfo.Program.ProgFD, ctx.egressPgmInfo.Program.ProgFD
}

var (
	repointPod = types.NamespacedName{Name: "db-0", Namespace: "prod"}
	sibling    = types.NamespacedName{Name: "db-1", Namespace: "prod"}
)

func TestAttach_RecordsIdentifierAndDeleteForgetsIt(t *testing.T) {
	client, _ := newRepointTestClient(t)

	_, err := client.AttacheBPFProbes(repointPod, "old@prod", 1, true)
	require.NoError(t, err)
	got, ok := client.AttachedPodIdentifier(repointPod)
	assert.True(t, ok)
	assert.Equal(t, "old@prod", got)

	// The caller's identifier may be stale; the recorded one is what gets released.
	require.NoError(t, client.DeleteBPFProbes(repointPod, "something-else@prod"))
	_, ok = client.AttachedPodIdentifier(repointPod)
	assert.False(t, ok)
	assert.False(t, client.HasBPFContext("old@prod"), "last pod gone: programs released")
}

func TestLoadBPFPrograms_LoadsOnceWithoutAttaching(t *testing.T) {
	client, replacer := newRepointTestClient(t)

	loaded, err := client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	assert.True(t, loaded)
	ingressFD, egressFD := progFDs(t, client, "new@prod")
	assert.NotZero(t, ingressFD)
	assert.NotZero(t, egressFD)

	loaded, err = client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	assert.False(t, loaded, "already loaded")
	again, _ := progFDs(t, client, "new@prod")
	assert.Equal(t, ingressFD, again)
	assert.Empty(t, replacer.calls)
	assert.False(t, client.identifierInUseLocked("new@prod"))
}

func TestRepoint_ReplacesFiltersInPlaceAndReleasesOldIdentifier(t *testing.T) {
	client, replacer := newRepointTestClient(t)
	_, err := client.AttacheBPFProbes(repointPod, "old@prod", 1, true)
	require.NoError(t, err)
	_, err = client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	newIngress, newEgress := progFDs(t, client, "new@prod")

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))

	assert.Equal(t, []replaceCall{
		{"enidb-00", tcHookEgress, newIngress},
		{"enidb-00", tcHookIngress, newEgress},
	}, replacer.calls, "one in-place replace per hook, never a detach")
	got, _ := client.AttachedPodIdentifier(repointPod)
	assert.Equal(t, "new@prod", got)
	assert.True(t, client.identifierInUseLocked("new@prod"))
	assert.False(t, client.HasBPFContext("old@prod"), "no pod left on the old identifier")
}

func TestRepoint_KeepsOldIdentifierWhileSiblingsUseIt(t *testing.T) {
	client, _ := newRepointTestClient(t)
	for _, pod := range []types.NamespacedName{repointPod, sibling} {
		_, err := client.AttacheBPFProbes(pod, "old@prod", 1, true)
		require.NoError(t, err)
	}
	_, err := client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))
	assert.True(t, client.HasBPFContext("old@prod"))
	assert.True(t, client.identifierInUseLocked("old@prod"))

	require.NoError(t, client.RepointBPFProbes(sibling, "new@prod", 1))
	assert.False(t, client.HasBPFContext("old@prod"))
}

func TestRepoint_RequiresLoadedPrograms(t *testing.T) {
	client, replacer := newRepointTestClient(t)
	_, err := client.AttacheBPFProbes(repointPod, "old@prod", 1, true)
	require.NoError(t, err)

	err = client.RepointBPFProbes(repointPod, "new@prod", 1)
	assert.ErrorContains(t, err, "not loaded")
	assert.Empty(t, replacer.calls)
	got, _ := client.AttachedPodIdentifier(repointPod)
	assert.Equal(t, "old@prod", got)
}

func TestRepoint_RollsBackPartialMove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failAt int
		// interfaces whose filters were changed before the failure and must be restored
		restored []string
	}{
		// interface 0 moves; interface 1's ingress replace fails and changes nothing
		{name: "ingress fails", failAt: 2, restored: []string{"enidb-00"}},
		// interface 1's ingress moves, then its egress fails: both interfaces go back
		{name: "egress fails", failAt: 3, restored: []string{"enidb-00", "enidb-01"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, replacer := newRepointTestClient(t)
			_, err := client.AttacheBPFProbes(repointPod, "old@prod", 2, true)
			require.NoError(t, err)
			oldIngress, oldEgress := progFDs(t, client, "old@prod")
			_, err = client.LoadBPFPrograms("new@prod")
			require.NoError(t, err)
			replacer.failAt = tc.failAt

			require.Error(t, client.RepointBPFProbes(repointPod, "new@prod", 2))

			var want []replaceCall
			for _, hostVeth := range tc.restored {
				want = append(want, replaceCall{hostVeth, tcHookEgress, oldIngress}, replaceCall{hostVeth, tcHookIngress, oldEgress})
			}
			assert.Equal(t, want, replacer.calls[tc.failAt+1:], "every interface touched goes back to the old programs")
			got, _ := client.AttachedPodIdentifier(repointPod)
			assert.Equal(t, "old@prod", got)
			assert.True(t, client.HasBPFContext("old@prod"))
		})
	}
}

func TestRepoint_AdoptsAnUnrecordedPodInPlace(t *testing.T) {
	// After a restart the client has no record of which pod uses which program, while the
	// pod's filters still point at the programs from before. The adopt must replace them in
	// place rather than detach and re-attach.
	client, replacer := newRepointTestClient(t)
	_, err := client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	ingressFD, egressFD := progFDs(t, client, "new@prod")

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))

	assert.Equal(t, []replaceCall{
		{"enidb-00", tcHookEgress, ingressFD},
		{"enidb-00", tcHookIngress, egressFD},
	}, replacer.calls)
	got, ok := client.AttachedPodIdentifier(repointPod)
	assert.True(t, ok)
	assert.Equal(t, "new@prod", got)
	assert.True(t, client.identifierInUseLocked("new@prod"))
}

func TestRepoint_FallsBackToAttachWhenAdoptCannotReplace(t *testing.T) {
	client, replacer := newRepointTestClient(t)
	_, err := client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	replacer.failAt = 0 // no clsact qdisc yet

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))
	got, ok := client.AttachedPodIdentifier(repointPod)
	assert.True(t, ok, "regular attach took over")
	assert.Equal(t, "new@prod", got)
}

func TestRepoint_AttachesWhenProgramsAreNotLoaded(t *testing.T) {
	client, replacer := newRepointTestClient(t)

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))
	got, ok := client.AttachedPodIdentifier(repointPod)
	assert.True(t, ok)
	assert.Equal(t, "new@prod", got)
	assert.Empty(t, replacer.calls, "nothing to adopt onto: regular attach loads and adds")
}

func TestRepoint_SkipsDeletedPod(t *testing.T) {
	client, replacer := newRepointTestClient(t)
	_, err := client.LoadBPFPrograms("new@prod")
	require.NoError(t, err)
	client.deletedPods.Store(utils.GetPodNamespacedName(repointPod.Name, repointPod.Namespace), struct{}{})

	require.NoError(t, client.RepointBPFProbes(repointPod, "new@prod", 1))
	_, ok := client.AttachedPodIdentifier(repointPod)
	assert.False(t, ok)
	assert.Empty(t, replacer.calls)
}

func TestRepoint_SameIdentifierIsANoop(t *testing.T) {
	client, replacer := newRepointTestClient(t)
	_, err := client.AttacheBPFProbes(repointPod, "same@prod", 1, true)
	require.NoError(t, err)

	require.NoError(t, client.RepointBPFProbes(repointPod, "same@prod", 1))
	assert.Empty(t, replacer.calls)
}

func TestReleaseUnusedPodIdentifiers(t *testing.T) {
	client, _ := newRepointTestClient(t)
	_, err := client.AttacheBPFProbes(repointPod, "used@prod", 1, true)
	require.NoError(t, err)
	for _, podIdentifier := range []string{"orphan@prod", "kept@prod"} {
		_, err := client.LoadBPFPrograms(podIdentifier)
		require.NoError(t, err)
	}

	released := client.ReleaseUnusedPodIdentifiers(map[string]bool{"kept@prod": true})

	assert.Equal(t, []string{"orphan@prod"}, released)
	assert.True(t, client.HasBPFContext("used@prod"), "an attached pod uses it")
	assert.True(t, client.HasBPFContext("kept@prod"), "in the keep set")
	assert.False(t, client.HasBPFContext("orphan@prod"))
}
