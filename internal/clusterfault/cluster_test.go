//go:build integration

package clusterfault

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/faultinject"
)

// ledgerZone is the primary zone every acknowledged write lands in.
const ledgerZone = "ledger.fault.test"

// member is one real Sable node in a fault-injection cluster.
type member struct {
	name          string
	directory     string
	ports         clustertest.Ports
	certificate   certificates.GeneratedCertificate
	configuration string
	client        *http.Client
	node          *clustertest.Node
	id            string
	binary        string   // the Sable binary the member runs
	environment   []string // added to the member's process environment
	restarted     func()   // when set, the member restarts on exit 75 and calls it
}

// faultCluster is a primary and its replicas, started as real processes.
type faultCluster struct {
	t       *testing.T
	members []*member
}

// startCluster starts size nodes, makes the first one primary with the
// ledger zone, joins the rest, and waits until every node is synchronized.
func startCluster(t *testing.T, size int) *faultCluster {
	t.Helper()
	return startClusterWith(t, size, nil)
}

// startClusterWith starts a cluster like startCluster, letting prepare adjust
// each member and its configuration before it first starts.
func startClusterWith(t *testing.T, size int, prepare func(*member, *config.Config)) *faultCluster {
	t.Helper()
	if size < 3 || size > 5 {
		t.Fatalf("fault clusters have 3 to 5 nodes, not %d", size)
	}
	faults := &faultCluster{t: t}
	for index := range size {
		faults.members = append(faults.members, newMember(t, fmt.Sprintf("node%d", index+1), prepare))
	}
	primary := faults.members[0]
	primary.start(t)
	clustertest.InitializePrimary(t, primary.client, primary.ports.HTTPS)
	createLedgerZone(t, primary)
	for _, replica := range faults.members[1:] {
		replica.start(t)
		enrollment := clustertest.CreateEnrollmentToken(t, primary.client, primary.ports.HTTPS)
		clustertest.JoinReplica(t, replica.client, replica.ports.HTTPS, primary.ports.HTTPS, enrollment.Token)
	}
	faults.waitSynchronized()
	for _, node := range faults.members {
		node.id = node.state(t).NodeID
	}
	return faults
}

func newMember(t *testing.T, name string, prepare func(*member, *config.Config)) *member {
	t.Helper()
	directory := t.TempDir()
	ports := clustertest.AllocatePorts(t)
	certificate := clustertest.GenerateClusterCertificate(t, directory, name)
	configuration := clustertest.NodeConfiguration(directory, ports, name, certificate)
	node := &member{
		name: name, directory: directory, ports: ports, certificate: certificate, binary: faultBinary,
		client: clustertest.TrustedHTTPClient(t, filepath.Join(directory, certificate.CAFile)),
	}
	if prepare != nil {
		prepare(node, &configuration)
	}
	node.configuration = clustertest.WriteConfiguration(t, directory, configuration)
	return node
}

func (node *member) start(t *testing.T) {
	t.Helper()
	environment := append([]string{faultinject.ControlEnv + "=" + node.controlFile()}, node.environment...)
	if node.restarted != nil {
		node.node = clustertest.StartSupervisedBinaryNode(t, node.binary, environment,
			node.configuration, node.client, node.ports.HTTPS, node.restarted)
		return
	}
	node.node = clustertest.StartBinaryNode(t, node.binary, environment, node.configuration, node.client, node.ports.HTTPS)
}

func (node *member) stop(t *testing.T) {
	t.Helper()
	node.client.CloseIdleConnections()
	clustertest.StopNode(t, node.node)
	node.node = nil
}

func (node *member) running() bool { return node.node != nil }

func (node *member) state(t *testing.T) cluster.State {
	t.Helper()
	return clustertest.FetchClusterState(t, node.client, node.ports.HTTPS)
}

// postForm sends a console form to the node and returns the response status.
func (node *member) postForm(path string, values url.Values) (int, error) {
	response, err := node.client.PostForm("https://"+node.ports.HTTPS+path, values)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func createLedgerZone(t *testing.T, primary *member) {
	t.Helper()
	status, err := primary.postForm("/ui/zones/add", url.Values{
		"name": {ledgerZone}, "type": {"primary"}, "primary_ns": {"ns1." + ledgerZone},
		"responsible": {"hostmaster@" + ledgerZone}, "default_ttl": {"60"},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create ledger zone = %d: %v", status, err)
	}
}

// primary returns the running node that reports itself primary.
func (faults *faultCluster) primary() *member {
	faults.t.Helper()
	for _, node := range faults.members {
		if node.running() && node.state(faults.t).LocalRole == cluster.RolePrimary {
			return node
		}
	}
	faults.t.Fatal("no running node reports itself primary")
	return nil
}

func (faults *faultCluster) running() []*member {
	var running []*member
	for _, node := range faults.members {
		if node.running() {
			running = append(running, node)
		}
	}
	return running
}

// waitSynchronized waits until every running node reports the same
// generation and primary, and the primary counts every running node
// synchronized.
func (faults *faultCluster) waitSynchronized() {
	faults.t.Helper()
	running := faults.running()
	var states []cluster.State
	clustertest.WaitForConditionWithDetails(faults.t, running[0].node, func() bool {
		states = states[:0]
		for _, node := range running {
			states = append(states, node.state(faults.t))
		}
		return synchronized(states, len(running))
	}, func() any { return states })
}

// synchronized reports whether every node follows one primary at one
// generation and that primary counts want nodes synchronized. Replicas only
// track the primary and themselves, so only the primary's count is checked.
func synchronized(states []cluster.State, want int) bool {
	if len(states) == 0 {
		return false
	}
	primaries := 0
	for _, state := range states {
		if !state.Initialized || state.Generation != states[0].Generation || state.PrimaryID != states[0].PrimaryID {
			return false
		}
		if state.LocalRole == cluster.RolePrimary {
			primaries++
			if state.Synchronized < want {
				return false
			}
		}
	}
	return primaries == 1
}
