package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
)

// The onboarding step used to be assigned in four places; this pins the one
// place that works it out now, including which signal wins.
func TestClusterOnboardingStepWorksOutTheStepInOnePlace(t *testing.T) {
	initialized, fresh := &cluster.State{Initialized: true}, &cluster.State{}
	get := func(target string) *http.Request { return httptest.NewRequest(http.MethodGet, target, nil) }
	post := func(target string, form url.Values) *http.Request {
		request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = request.ParseForm()
		return request
	}
	https := url.Values{"workflow": {"primary"}, "wizard_step": {"https"}}
	for _, test := range []struct {
		name    string
		request *http.Request
		state   *cluster.State
		want    clusterOnboardingStep
	}{
		{"initialized", get("/cluster"), initialized, clusterOnboardingFinal},
		{"fresh node reviews its settings", get("/cluster?onboarding=primary"), fresh, clusterOnboardingNode},
		{"no request on a fresh node", nil, fresh, clusterOnboardingNode},
		{"resume after saving", get("/cluster?onboarding=primary&resume=ready"), fresh, clusterOnboardingFinal},
		{"failed join resumes", post("/ui/cluster/join", url.Values{"workflow": {"join"}}), fresh, clusterOnboardingFinal},
		{"configure node", get("/cluster?configure=node"), initialized, clusterOnboardingNode},
		{"configure https", get("/cluster?configure=https"), initialized, clusterOnboardingHTTPS},
		{"https form", post("/ui/cluster/onboarding", https), initialized, clusterOnboardingHTTPS},
		{"https form wins over a fresh node", post("/ui/cluster/onboarding", https), fresh, clusterOnboardingHTTPS},
		{"https form needs a workflow", post("/ui/cluster/onboarding", url.Values{"wizard_step": {"https"}}), initialized, clusterOnboardingFinal},
		{"no cluster service: query only", get("/cluster?configure=https"), nil, clusterOnboardingHTTPS},
		{"no cluster service ignores the form", post("/ui/cluster/onboarding", https), nil, clusterOnboardingFinal},
	} {
		if got := clusterOnboardingStepFor(test.request, test.state); got != test.want {
			t.Errorf("%s = %d, want %d", test.name, got, test.want)
		}
	}
	for step, want := range map[clusterOnboardingStep][2]any{
		clusterOnboardingFinal: {false, 1}, clusterOnboardingNode: {true, 1}, clusterOnboardingHTTPS: {true, 2},
	} {
		if configure, number := step.view(); configure != want[0] || number != want[1] {
			t.Errorf("step %d view = %v, %d; want %v, %v", step, configure, number, want[0], want[1])
		}
	}
}
