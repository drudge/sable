package pages

import (
	"context"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/blocking"
)

func TestCatalogOffersURLhausFromAbuseCHOnlyWithAKey(t *testing.T) {
	t.Parallel()

	urlhaus := func(catalog []BlockListCatalogItem) BlockListCatalogItem {
		for _, item := range catalog {
			if item.Name == "URLhaus Malicious URLs" {
				return item
			}
		}
		t.Fatal("URLhaus is missing from the catalog")
		return BlockListCatalogItem{}
	}
	if item := urlhaus(catalogFor(false)); item.URL != blocking.URLhausURL || catalogLink(item) != blocking.URLhausURL {
		t.Fatalf("keyless URLhaus = %+v", item)
	}
	keyed := urlhaus(catalogFor(true))
	if keyed.URL != blocking.URLhausKeyedURL || catalogLink(keyed) != "https://urlhaus.abuse.ch/" {
		t.Fatalf("keyed URLhaus = %+v", keyed)
	}
	if urlhaus(blockListCatalog).URL != blocking.URLhausURL {
		t.Fatal("offering the keyed URL changed the shared catalog")
	}
	mirror := []BlockListSourceView{{Name: "URLhaus Malicious URLs", URL: blocking.URLhausURL}}
	if !blockListAdded(mirror, keyed) {
		t.Fatal("the keyed URLhaus was offered beside a mirror subscription with the same name")
	}
}

func TestKeyedBlockListRowSaysItUsesTheAuthKey(t *testing.T) {
	t.Parallel()

	var rendered strings.Builder
	list := BlockListSourceView{Name: "URLhaus Malicious URLs", URL: blocking.URLhausKeyedURL, Format: "auto", Healthy: true}
	if err := BlockListRow(list).Render(context.Background(), &rendered); err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	if !strings.Contains(html, "Downloads with your abuse.ch Auth-Key") || strings.Contains(html, blocking.AbuseCHKeyPlaceholder) {
		t.Fatalf("keyed row = %s", html)
	}
	if !strings.Contains(html, "urlhaus-api.abuse.ch/v2/files/exports/&lt;Auth-Key&gt;/hostfile.txt") {
		t.Fatalf("keyed row does not show where the key goes: %s", html)
	}
}
