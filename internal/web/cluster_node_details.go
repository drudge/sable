package web

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/web/pages"
)

// clusterNodePanel fills the details panel for one node. With part=details
// it sends only the part of the panel that refreshes itself while open.
func (server *Server) clusterNodePanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	view := server.clusterNodeDrawerView(request, strings.TrimSpace(request.URL.Query().Get("name")))
	component := pages.ClusterNodeDrawer(view)
	if request.URL.Query().Get("part") == "details" && !view.Missing {
		component = pages.ClusterNodeDetails(view)
	}
	server.render(writer, request, component)
}

// clusterNodeDrawerView finds a node by the name or ID in its address and
// gathers the problems it has reported.
func (server *Server) clusterNodeDrawerView(request *http.Request, key string) pages.ClusterNodeDrawerView {
	view := pages.ClusterNodeDrawerView{Key: key, Missing: true}
	if server.cluster == nil || key == "" {
		return view
	}
	state := server.cluster.Snapshot()
	page := pages.ClusterPageView{Console: pages.DashboardView{TimeDisplay: requestTimeDisplay(request)}}
	populateClusterStateView(&page, state)
	index := slices.IndexFunc(page.Nodes, func(node pages.ClusterNodeView) bool { return node.ID == key })
	if index < 0 {
		index = slices.IndexFunc(page.Nodes, func(node pages.ClusterNodeView) bool { return node.Name == key })
	}
	if !state.Initialized || index < 0 {
		return view
	}
	view.Missing, view.Node, view.LocalRole = false, page.Nodes[index], page.LocalRole
	// Only the primary keeps what each replica reports about itself.
	view.ProblemsKnown = (view.Node.Local && server.alerts != nil) || (!view.Node.Local && state.LocalRole == cluster.RolePrimary)
	if !view.ProblemsKnown {
		return view
	}
	for _, alert := range server.clusterNodeProblems(request.Context(), state, time.Now())[view.Node.ID] {
		// The panel already names the node, so the title stands without the
		// alert's subject.
		problem := pages.ClusterNodeProblemView{Title: alert.Title, Detail: alert.Headline}
		if problem.Title == "" {
			problem.Title, problem.Detail = alertProblemText(alert), ""
		}
		// A replica's page paths are on its own console, not this one.
		if view.Node.Local && strings.HasPrefix(alert.Path, "/") {
			problem.Path = alert.Path
		}
		view.Problems = append(view.Problems, problem)
	}
	return view
}

// clusterNodeLink is the address of a node's panel: its name, unless another
// node shares it, then its ID.
func clusterNodeLink(node cluster.Node, nodes []cluster.Node) string {
	shared := slices.ContainsFunc(nodes, func(other cluster.Node) bool { return other.ID != node.ID && other.Name == node.Name })
	if node.Name == "" || shared {
		return pages.ClusterNodePath(node.ID)
	}
	return pages.ClusterNodePath(node.Name)
}
