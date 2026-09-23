package web

import (
	"testing"

	"github.com/drudge/sable/internal/web/pages"
)

func TestBusiestDevicesLinkOnlyWhenOneAddressReproducesTheCount(t *testing.T) {
	t.Parallel()
	ranking := busiestDeviceRanking([]pages.InsightDeviceView{
		{Label: "george-laptop", Queries: 900, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.5"}, {Address: "fd00::5"}}},
		{Label: "front-door-doorbell", Queries: 240, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.46"}}},
		{Label: "10.0.0.9", Queries: 12, Addresses: []pages.InsightDeviceAddressView{{Address: "10.0.0.9"}}},
	}, "start=a&end=b")
	if ranking[0].Href != "" || ranking[0].Secondary != "2 addresses" {
		t.Errorf("multi-address device = %+v", ranking[0])
	}
	if ranking[1].Href != "/logs?tab=queries&client_ip=10.0.0.46&start=a&end=b" || ranking[1].Secondary != "10.0.0.46" {
		t.Errorf("single-address device = %+v", ranking[1])
	}
	if ranking[2].Secondary != "" {
		t.Errorf("an address-only device repeats its address: %+v", ranking[2])
	}
}
