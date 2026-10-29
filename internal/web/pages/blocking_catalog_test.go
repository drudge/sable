package pages

import (
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
