package web

import (
	"context"
	"regexp"
	"strings"
	"testing"

	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/web/pages"
)

// Every kind of finding has an icon the console can draw; an icon name the
// console does not know draws an empty square.
func TestInsightFindingIconsDraw(t *testing.T) {
	t.Parallel()
	shapes := regexp.MustCompile(`<(path|circle|rect|line|polyline)\b`)
	for _, kind := range []string{
		blockinginsights.KindPastBlock, blockinginsights.KindUpdateFailing, blockinginsights.KindListUnreadable,
		blockinginsights.KindLowUnique, blockinginsights.KindUniqueCoverage,
		devices.KindNewDevice, devices.KindNewDestinations, devices.KindTrafficSpike, devices.KindWentQuiet,
		devices.KindNewApp, devices.KindUnusualHours, devices.KindCheckIn, devices.KindApplianceDrift,
	} {
		var drawn strings.Builder
		if err := pages.Icon(insightFindingIcon(kind)).Render(context.Background(), &drawn); err != nil {
			t.Fatal(err)
		}
		if !shapes.MatchString(drawn.String()) {
			t.Errorf("%s icon %q draws nothing", kind, insightFindingIcon(kind))
		}
	}
	for kind, want := range map[string]string{devices.KindUnusualHours: "clock-alert", devices.KindNewDevice: "circle-plus", devices.KindNewApp: "grid-2x2-plus"} {
		if icon := insightFindingIcon(kind); icon != want {
			t.Errorf("%s shows %q, want %q", kind, icon, want)
		}
	}
}

// Every busiest device opens its drawer, including one with several addresses
// that no single query log link could reproduce.
func TestBusiestDevicesOpenTheirDrawers(t *testing.T) {
	t.Parallel()
	ranking := busiestDeviceRanking([]pages.InsightDeviceView{
		{Key: "mac:3c:22:fb:01:02:03", Label: "george-laptop", Queries: 900, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.5"}, {Address: "fd00::5"}}},
		{Key: "mac:34:3e:a4:33:0c:c6", Label: "front-door-doorbell", Queries: 240, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.46"}}},
		{Key: "ip:10.0.0.9", Label: "10.0.0.9", Queries: 12, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.9"}}},
	}, "day")
	for index, secondary := range []string{"2 addresses", "10.0.0.46", ""} {
		if ranking[index].Secondary != secondary {
			t.Errorf("%s secondary = %q, want %q", ranking[index].Name, ranking[index].Secondary, secondary)
		}
	}
	for _, item := range ranking {
		if item.Href != "" || item.Drawer == nil || item.Drawer.Dialog != "insight-device-dialog" {
			t.Errorf("%s does not open its drawer: %+v", item.Name, item)
		}
	}
	if url := ranking[0].Drawer.URL; url != "/ui/insights/device?key=mac%3A3c%3A22%3Afb%3A01%3A02%3A03&range=day" {
		t.Errorf("drawer URL = %q", url)
	}
}
