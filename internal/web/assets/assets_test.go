package assets

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFingerprintURLServesImmutableCompressedAsset(t *testing.T) {
	t.Parallel()

	path := URL("app.js")
	if !strings.HasPrefix(path, "/assets/") || !strings.HasSuffix(path, "/app.js") || path == "/assets/app.js" {
		t.Fatalf("URL(app.js) = %q, want a fingerprinted path", path)
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept-Encoding", "br, gzip")
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("asset status = %d", response.Code)
	}
	if got := response.Header().Get("Cache-Control"); got != immutableCachePolicy {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := response.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q", got)
	}
	if response.Header().Get("ETag") == "" {
		t.Fatal("ETag is empty")
	}
	reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, manifest["app.js"].content) {
		t.Fatal("compressed response does not expand to app.js")
	}
}

func TestAssetETagReturnsNotModified(t *testing.T) {
	t.Parallel()

	path := URL("app.css")
	firstRequest := httptest.NewRequest(http.MethodGet, path, nil)
	firstRequest.Header.Set("Accept-Encoding", "gzip")
	first := httptest.NewRecorder()
	Handler().ServeHTTP(first, firstRequest)

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("If-None-Match", first.Header().Get("ETag"))
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("conditional asset response = %d, %d bytes", response.Code, response.Body.Len())
	}
	if response.Header().Get("Cache-Control") != immutableCachePolicy {
		t.Fatal("304 response lost immutable caching")
	}
}

func TestLegacyAssetPathRevalidatesAndWrongFingerprintFails(t *testing.T) {
	t.Parallel()

	legacy := httptest.NewRecorder()
	Handler().ServeHTTP(legacy, httptest.NewRequest(http.MethodGet, "/assets/sable-mark.svg", nil))
	if legacy.Code != http.StatusOK || legacy.Header().Get("Cache-Control") != legacyCachePolicy {
		t.Fatalf("legacy response = %d, Cache-Control %q", legacy.Code, legacy.Header().Get("Cache-Control"))
	}

	missing := httptest.NewRecorder()
	Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/assets/not-the-hash/sable-mark.svg", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("wrong fingerprint status = %d, want 404", missing.Code)
	}
}

func TestGzipQualityZeroKeepsIdentityRepresentation(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, URL("app.css"), nil)
	request.Header.Set("Accept-Encoding", "gzip;q=0.0, br")
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding = %q, want identity", response.Header().Get("Content-Encoding"))
	}
	if !bytes.Equal(response.Body.Bytes(), manifest["app.css"].content) {
		t.Fatal("identity response does not match app.css")
	}
}

func TestVendoredHTMXVersion(t *testing.T) {
	t.Parallel()

	if content := string(manifest["htmx.min.js"].content); !strings.Contains(content, `version="4.0.0"`) {
		t.Fatal("vendored htmx asset is not version 4.0.0")
	}
}

func TestAccessibilityInteractionAssets(t *testing.T) {
	t.Parallel()

	script := string(manifest["app.js"].content)
	for _, expected := range []string{
		"const tabFromKey", "setupDialogAccessibility", "setupScrollableRegion",
		"Live log updates paused", "data-chart-keyboard-status", "sidebar-mobile-open",
		`!control.closest("[hidden]")`, `mobileOpen ? "Close navigation" : "Open navigation"`,
		"setupCommandPalette", "sable-command", "sable-search", "commandRank", "commandAcronym", "beginSearch", "selectSearchMode", "commandSearchModesConfig", "commandSearchModeExtraParam", "commandSearchModeValueTarget", "searchModeFooterItems", `["ArrowLeft", "ArrowRight"].includes(event.key)`, "requestSubmit", "runSearch", "runPostCommand", "visibleDialogTrigger", `target.closest("dialog")`, "responseDocument", "toast-region", "commandValues", `event.key.toLowerCase() !== "k"`, "data-record-dialog-row", "recordInteractive",
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("application script does not contain accessibility behavior %q", expected)
		}
	}

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{".skip-links", ".command-palette", ":focus-visible", "prefers-reduced-motion", "forced-colors"} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("application stylesheet does not contain accessibility rule %q", expected)
		}
	}
}

func TestSidebarTracksTheVisibleMobileViewport(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, "height: 100vh;\n  height: 100dvh;") {
		t.Fatal("sidebar does not provide a legacy viewport fallback followed by a dynamic viewport height")
	}
}

func TestNativeSelectOptionsRemainReadableOnLightPopups(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, "select option, select optgroup { background-color: #fff; color: #171717; }") {
		t.Fatal("native select options do not override inherited dark-theme text")
	}
}

func TestStyledSelectOwnsItsThemeAndKeyboardBehavior(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{".styled-select-trigger", ".styled-select-popover", `.styled-select[data-side="top"]`, ".styled-select-option.placeholder", "background: var(--popover)"} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("application stylesheet does not contain styled select rule %q", expected)
		}
	}

	script := string(manifest["app.js"].content)
	for _, expected := range []string{"setupStyledSelect", `option.hasAttribute("data-placeholder")`, "MutationObserver", `role", "combobox`, `role", "listbox`, `event.key === "ArrowDown"`, `event.key === "Escape"`} {
		if !strings.Contains(script, expected) {
			t.Errorf("application script does not contain styled select behavior %q", expected)
		}
	}
}

func TestCustomControlTriggersMatchTextFields(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, selector := range []string{"\n.styled-select-trigger {", "\n.range-trigger {", "\n.resolver-trigger {"} {
		_, afterSelector, found := strings.Cut(stylesheet, selector)
		if !found {
			t.Fatalf("application stylesheet does not define %s", strings.TrimSpace(selector))
		}
		rule, _, found := strings.Cut(afterSelector, "}")
		if !found {
			t.Fatalf("application stylesheet has an incomplete %s rule", strings.TrimSpace(selector))
		}
		for _, expected := range []string{"height: 2.25rem", "border-radius: calc(var(--radius) - 2px)", "background: transparent", "padding: 0 .75rem", "font-size: .875rem"} {
			if !strings.Contains(rule, expected) {
				t.Errorf("%s does not match text fields: missing %q", strings.TrimSpace(selector), expected)
			}
		}
		if strings.Contains(rule, "box-shadow:") {
			t.Errorf("%s adds a resting shadow that text fields do not have", strings.TrimSpace(selector))
		}
	}
	for _, hoverRule := range []string{".styled-select-trigger:hover", ".range-trigger:hover"} {
		if strings.Contains(stylesheet, hoverRule) {
			t.Errorf("%s has a hover border state that text fields do not", hoverRule)
		}
	}
	if !strings.Contains(stylesheet, `.range-trigger[aria-expanded="true"] .styled-select-chevron`) {
		t.Error("range trigger does not animate the shared chevron when opened")
	}
	if !strings.Contains(stylesheet, `.resolver-trigger[aria-expanded="true"] .styled-select-chevron`) {
		t.Error("resolver trigger does not animate the shared chevron when opened")
	}
}

func TestRangeCalendarUsesStyledMonthAndYearSelects(t *testing.T) {
	t.Parallel()

	script := string(manifest["app.js"].content)
	for _, expected := range []string{"sableSyncStyledSelect", "monthSelect.sableSyncStyledSelect?.()", "yearSelect.sableSyncStyledSelect?.()", `event.key !== "Escape" || event.defaultPrevented`} {
		if !strings.Contains(script, expected) {
			t.Errorf("range calendar does not synchronize styled select behavior %q", expected)
		}
	}
	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, ".calendar-dropdowns .styled-select-trigger") {
		t.Error("range calendar does not size its styled select triggers")
	}
	if !strings.Contains(stylesheet, `.chart-card:has(.range-popover:not([hidden])) { overflow: visible; }`) {
		t.Error("open dashboard range picker remains clipped by its card")
	}
}

func TestStyledTimePickerOwnsItsThemeAndKeyboardBehavior(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{".styled-time-trigger", ".styled-time-entry", ".styled-time-toggle", ".styled-time-popover", ".styled-time-columns", `.styled-time[data-side="top"]`} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("application stylesheet does not contain styled time rule %q", expected)
		}
	}

	script := string(manifest["app.js"].content)
	for _, expected := range []string{"setupStyledTime", "uses24HourTime", "parseTimeEntry", "selectTimeSegment", "moveTimeSegment", "typeTimeDigit", "positionAnchoredPopover", `event.key === "ArrowDown"`, `event.key === "Escape"`} {
		if !strings.Contains(script, expected) {
			t.Errorf("application script does not contain styled time behavior %q", expected)
		}
	}
}

func TestStyledTimePickerMatchesTextFieldGeometryAndSurface(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	_, afterSelector, found := strings.Cut(stylesheet, ".styled-time-trigger {")
	if !found {
		t.Fatal("application stylesheet does not define the styled time trigger")
	}
	rule, _, found := strings.Cut(afterSelector, "}")
	if !found {
		t.Fatal("styled time trigger rule is incomplete")
	}
	for _, expected := range []string{"box-sizing: border-box", "height: 2.25rem", "background: transparent"} {
		if !strings.Contains(rule, expected) {
			t.Errorf("styled time trigger does not match text fields: missing %q", expected)
		}
	}
	if strings.Contains(stylesheet, ".styled-time-trigger:hover") {
		t.Error("styled time trigger has a hover border state that text fields do not")
	}
	_, mobileStyles, found := strings.Cut(stylesheet, "@media (max-width: 767px)")
	if !found || !strings.Contains(mobileStyles, ".styled-time-popover { width: 100%; }") {
		t.Error("styled time picker does not span its field on mobile")
	}
	if !strings.Contains(mobileStyles, ".range-times .styled-time-popover { width: calc(200% + .5rem); }") {
		t.Error("range time picker does not span both narrow time fields on mobile")
	}
}

func TestCertificateChoiceInputsCannotCreateHorizontalOverflow(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	selector := ".certificate-mode-control input, .cluster-certificate-choices > label > input {"
	_, afterSelector, found := strings.Cut(stylesheet, selector)
	if !found {
		t.Fatal("application stylesheet does not constrain hidden certificate choice inputs")
	}
	rule, _, found := strings.Cut(afterSelector, "}")
	if !found {
		t.Fatal("hidden certificate choice input rule is incomplete")
	}
	for _, expected := range []string{"position: absolute", "width: 1px", "height: 1px", "overflow: hidden", "clip-path: inset(50%)"} {
		if !strings.Contains(rule, expected) {
			t.Errorf("hidden certificate choice inputs can expand the page: missing %q", expected)
		}
	}
}

func TestIntegrationActionsStackAcrossTheMobileCard(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	expected := ".integration-card-actions-primary { width: 100%; align-items: stretch; flex-direction: column; }"
	if !strings.Contains(stylesheet, expected) {
		t.Errorf("mobile integration actions do not fill and stack within the card: missing %q", expected)
	}
	if !strings.Contains(stylesheet, ".integration-card-actions .button, .integration-card-actions form { width: 100%; justify-content: center; }") {
		t.Error("mobile integration action buttons do not fill their available row")
	}
}

func TestOpenZoneActionMenuStacksAboveSiblingButtons(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, ".zone-action-menu[open] { z-index: 30; }") {
		t.Error("open zone action menu does not stack above closed sibling menus")
	}
}

func TestDialogFooterButtonsCenterFullWidthMobileLabels(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, ".dialog-footer .button { display: inline-flex; align-items: center; justify-content: center;") {
		t.Error("dialog footer buttons do not center their contents when expanded on mobile")
	}
}

func TestMobileBackupActionsCenterButtonContents(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, ".backup-local-actions .button { justify-content: center;") {
		t.Error("mobile backup action buttons do not center their icon and label")
	}
}

func TestQueryLogToolbarUsesAvailableCompactWidth(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{
		"@media (min-width: 561px) and (max-width: 960px)",
		".query-logs-toolbar { align-items: center; flex-direction: row; }",
		".query-logs-toolbar .logs-toolbar-actions { display: flex; flex: none; }",
	} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("compact query-log toolbar does not use available horizontal space: missing %q", expected)
		}
	}
}

func TestQueryLogFilterCaretUsesSplitButtonAlignment(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{
		".filters-toggle { gap: .4rem; overflow: hidden; padding-right: 0; }",
		".filters-toggle .button-caret { display: grid; width: 2.15rem; align-self: stretch; flex: 0 0 2.15rem; place-items: center;",
		".filters-toggle .button-caret .nav-icon { width: .75rem; height: .75rem;",
	} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("query-log Filters button does not align its caret segment: missing %q", expected)
		}
	}
}

func TestQueryLogFiltersAnimateFromToolbar(t *testing.T) {
	t.Parallel()

	script := string(manifest["app.js"].content)
	for _, expected := range []string{
		"const animateFiltersPanel = (open) =>",
		"const fullHeight = filtersPanel.scrollHeight",
		`filtersPanel.style.transformOrigin = "top right"`,
		"filtersPanel.animate(open ? [",
		`window.matchMedia("(prefers-reduced-motion: reduce)").matches`,
		"if (!open) filtersPanel.setAttribute(\"hidden\", \"\")",
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("query-log filter panel does not animate from its toolbar control: missing %q", expected)
		}
	}
}

func TestMobileLogTabsSpanAvailableWidth(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	_, mobileStyles, found := strings.Cut(stylesheet, "@media (max-width: 700px)")
	if !found || !strings.Contains(mobileStyles, ".logs-tab-list { width: 100%; grid-template-columns: repeat(2, minmax(0, 1fr)); }") {
		t.Error("mobile log tabs do not span the available content width")
	}
}

func TestAdministrationMobileRowsKeepChevronAtRightEdge(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	if !strings.Contains(stylesheet, ".admin-mobile-row { display: flex; width: 100%;") {
		t.Error("administration mobile rows do not use the flex layout required to align their chevron")
	}
}

func TestAdministrationMobileRowsUseTrailingStatusAndGroupTags(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{
		".admin-mobile-user-row > div.admin-mobile-user-copy { grid-template-columns: minmax(0, 1fr); gap: .35rem; }",
		".admin-mobile-user-meta { display: flex; min-width: 0; flex-wrap: wrap; align-items: center;",
		".admin-mobile-user-trailing, .admin-mobile-group-trailing { display: flex; flex: 0 0 auto; align-items: center;",
		".admin-mobile-user-statuses { display: flex; align-items: center; gap: .3rem; }",
		".admin-mobile-user-statuses .sso-badge { margin-left: 0; }",
		".mobile-role-list { display: flex; min-width: 0; flex-wrap: wrap;",
		".table-badges > span, .mobile-role-list > span, .count-badge, .token-type-badge",
	} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("administration mobile rows do not align status and group tags: missing %q", expected)
		}
	}
}

func TestAdministrationMobileTabsUseBalancedRows(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	_, mobileStyles, found := strings.Cut(stylesheet, "@media (max-width: 700px)")
	for _, expected := range []string{
		".admin-tab-list { display: grid; width: 100%; grid-template-columns: repeat(6, minmax(0, 1fr));",
		".admin-tab-list .isotope-tab { width: 100%; grid-column: span 2; }",
		".admin-tab-list .isotope-tab:nth-child(n + 4) { grid-column: span 3; }",
	} {
		if !found || !strings.Contains(mobileStyles, expected) {
			t.Errorf("mobile administration tabs do not form balanced three-then-two rows: missing %q", expected)
		}
	}
}

func TestAdministrationMobileGroupAlignsMemberBadgeWithChevron(t *testing.T) {
	t.Parallel()

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{
		".admin-mobile-group-row > div.admin-mobile-group-copy { grid-template-columns: minmax(0, 1fr); gap: .35rem; }",
		".admin-mobile-user-trailing, .admin-mobile-group-trailing { display: flex; flex: 0 0 auto; align-items: center;",
		".admin-mobile-user-trailing .nav-icon, .admin-mobile-group-trailing .nav-icon",
	} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("mobile group rows do not align the member badge with the chevron: missing %q", expected)
		}
	}
}
