(() => {
  const themeKey = "sable-theme";
  const sidebarKey = "sable-sidebar-collapsed";
  const systemDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;
  const currentTheme = () => ["light", "dark"].includes(localStorage.getItem(themeKey)) ? localStorage.getItem(themeKey) : "system";
  const dark = currentTheme() === "dark" || (currentTheme() === "system" && systemDark());
  document.documentElement.classList.toggle("dark", dark);

  if (localStorage.getItem(sidebarKey) === "true") {
    document.documentElement.classList.add("sidebar-collapsed");
  }

  // Timestamps render on the server, so tell it which zone this browser is in.
  // Without this a server running on UTC shows every time shifted.
  const timeZoneCookie = "sable_time_zone";
  const readCookie = (name) => document.cookie.split("; ").find((entry) => entry.startsWith(`${name}=`))?.slice(name.length + 1) ?? "";
  let browserTimeZone = "";
  try { browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { browserTimeZone = ""; }
  if (/^[A-Za-z0-9_+\-/]{1,64}$/.test(browserTimeZone) && readCookie(timeZoneCookie) !== browserTimeZone) {
    document.cookie = `${timeZoneCookie}=${browserTimeZone}; Path=/; Max-Age=31536000; SameSite=Lax`;
    // Only reload once the cookie actually stuck, otherwise this would loop.
    if (readCookie(timeZoneCookie) === browserTimeZone) window.location.reload();
  }

	document.addEventListener("DOMContentLoaded", () => {
	const replicaLocalMutation = (path) => {
	  if (path === "/login" || path === "/logout" || path === "/ui/query" || path === "/ui/administration/sessions/revoke") return true;
	  if (path.startsWith("/ui/cache/") || path.startsWith("/api/v1/cache/")) return true;
	  if (path.startsWith("/ui/certificates/")) return true;
	  if (path === "/ui/cluster/settings" || path === "/ui/cluster/leave" || path === "/ui/cluster/restart" || path === "/api/v1/cluster/membership") return true;
	  return path.endsWith("/promote") && (path.startsWith("/ui/cluster/nodes/") || path.startsWith("/api/v1/cluster/nodes/"));
	};
	const mutationPath = (element) => {
	  const value = element.getAttribute?.("hx-post") || element.getAttribute?.("hx-delete") ||
		(element.tagName === "FORM" && element.getAttribute("method")?.toLowerCase() === "post" ? element.getAttribute("action") || window.location.pathname : "");
	  if (!value) return "";
	  try { return new URL(value, window.location.origin).pathname; } catch { return value.split("?")[0]; }
	};
	const markReplicaPrimaryOnly = (element) => {
	  if (!element || element.dataset.replicaPrimaryOnly === "true") return;
	  element.dataset.replicaPrimaryOnly = "true";
	  element.setAttribute("aria-disabled", "true");
	  element.title = "This change must be made on the cluster primary.";
	  if ("disabled" in element) element.disabled = true;
	};
	const setupReplicaReadOnly = (root) => {
	  if (document.body?.dataset.controlPlaneReadOnly !== "true" || !root) return;
	  const candidates = [];
	  if (root.matches?.('form[hx-post], form[hx-delete], form[method="post"], [hx-post], [hx-delete]')) candidates.push(root);
	  candidates.push(...(root.querySelectorAll?.('form[hx-post], form[hx-delete], form[method="post"], [hx-post], [hx-delete]') || []));
	  [...new Set(candidates)].forEach((candidate) => {
		const path = mutationPath(candidate);
		if (!path || replicaLocalMutation(path)) return;
		if (candidate.tagName === "FORM") {
		  candidate.dataset.replicaReadOnlyForm = "true";
		  candidate.querySelectorAll('button:not([type]), button[type="submit"], input[type="submit"], input[type="image"]').forEach(markReplicaPrimaryOnly);
		  candidate.querySelectorAll('input:not([type="hidden"]):not([type="button"]):not([type="reset"]), textarea, select').forEach(markReplicaPrimaryOnly);
		  if (candidate.id) {
			document.querySelectorAll(`[form="${CSS.escape(candidate.id)}"]`).forEach((control) => {
			  if (control.matches('input[type="hidden"], input[type="button"], input[type="reset"], button[type="button"], button[type="reset"]')) return;
			  markReplicaPrimaryOnly(control);
			});
		  }
		} else {
		  markReplicaPrimaryOnly(candidate);
		}
	  });
	  const mutationLaunchers = [];
	  if (root.matches?.("[data-replica-primary-action]")) mutationLaunchers.push(root);
	  mutationLaunchers.push(...(root.querySelectorAll?.("[data-replica-primary-action]") || []));
	  mutationLaunchers.forEach(markReplicaPrimaryOnly);
	};

	const setupResolverCombobox = (root) => {
	  const trigger = root.querySelector("[data-resolver-trigger]");
	  const popover = root.querySelector("[data-resolver-popover]");
	  const search = root.querySelector("[data-resolver-search]");
	  const selectedValue = root.querySelector("[data-resolver-value]");
	  const selectedLabel = root.querySelector("[data-resolver-label]");
	  const empty = root.querySelector("[data-resolver-empty]");
	  const dialog = root.closest("form")?.querySelector("[data-custom-dialog]");
	  if (!trigger || !popover || !search || !selectedValue || !selectedLabel || !dialog) return;

	  const customName = root.querySelector("[data-custom-name]");
	  const customIP = root.querySelector("[data-custom-ip]");
	  const customOption = root.querySelector("[data-resolver-custom-option]");
	  const customOptionLabel = root.querySelector("[data-resolver-custom-label]");
	  const customEdit = root.querySelector("[data-resolver-custom-edit]");
	  const draftName = dialog.querySelector("[data-custom-name-draft]");
	  const draftIP = dialog.querySelector("[data-custom-ip-draft]");
	  const preview = dialog.querySelector("[data-custom-preview]");
	  const previewValue = dialog.querySelector("[data-custom-preview-value]");
	  const applyButton = dialog.querySelector("[data-custom-apply]");

	  const allOptions = () => [...root.querySelectorAll("[data-resolver-option]")];
	  const focusableRows = () => [...root.querySelectorAll("[data-resolver-option], [data-resolver-custom-edit]")]
		.filter((row) => !row.hidden && !row.closest("[data-resolver-group]")?.hidden);

	  const closePopover = ({restoreFocus = false} = {}) => {
		popover.hidden = true;
		trigger.setAttribute("aria-expanded", "false");
		if (restoreFocus) trigger.focus();
	  };

	  const filterOptions = () => {
		const query = search.value.trim().toLowerCase();
		allOptions().forEach((option) => {
		  if (option === customOption && !customOptionLabel.textContent) {
			option.hidden = true;
			return;
		  }
		  option.hidden = !(option.dataset.search || option.textContent).toLowerCase().includes(query);
		});
		customEdit.hidden = !customEdit.dataset.search.includes(query);
		root.querySelectorAll("[data-resolver-group]").forEach((group) => {
		  group.hidden = ![...group.querySelectorAll("[data-resolver-option], [data-resolver-custom-edit]")]
			.some((row) => !row.hidden);
		});
		empty.hidden = root.querySelectorAll("[data-resolver-group]:not([hidden])").length > 0;
	  };

	  const openPopover = () => {
		popover.hidden = false;
		trigger.setAttribute("aria-expanded", "true");
		search.value = "";
		filterOptions();
		search.focus();
	  };

	  const choose = (option) => {
		selectedValue.value = option.dataset.resolverOption;
		selectedLabel.textContent = option.dataset.resolverLabelValue;
		allOptions().forEach((candidate) => {
		  const active = candidate === option;
		  candidate.setAttribute("aria-selected", String(active));
		});
		closePopover({restoreFocus: true});
	  };

	  const customDisplay = () => {
		const name = draftName.value.trim();
		const ip = draftIP.value.trim();
		return name && ip ? `${name} (${ip})` : ip || name;
	  };

	  const updateCustomDraft = () => {
		const display = customDisplay();
		preview.hidden = !display;
		previewValue.textContent = display;
		applyButton.disabled = !display;
	  };

	  const openCustomDialog = () => {
		closePopover();
		draftName.value = customName.value;
		draftIP.value = customIP.value;
		updateCustomDraft();
		dialog.showModal();
		draftName.focus();
	  };

	  const applyCustom = () => {
		const display = customDisplay();
		if (!display) return;
		customName.value = draftName.value.trim();
		customIP.value = draftIP.value.trim();
		customOptionLabel.textContent = display;
		customOption.dataset.resolverLabelValue = display;
		customOption.dataset.search = `custom ${display}`;
		customOption.hidden = false;
		customEdit.querySelector("span").textContent = "Edit custom server...";
		choose(customOption);
		dialog.close();
	  };

	  trigger.addEventListener("click", () => {
		if (popover.hidden) openPopover(); else closePopover({restoreFocus: true});
	  });
	  search.addEventListener("input", filterOptions);
	  search.addEventListener("keydown", (event) => {
		if (event.key === "ArrowDown") {
		  event.preventDefault();
		  focusableRows()[0]?.focus();
		} else if (event.key === "Escape") {
		  event.preventDefault();
		  closePopover({restoreFocus: true});
		}
	  });
	  root.addEventListener("keydown", (event) => {
		if (!event.target.matches("[data-resolver-option], [data-resolver-custom-edit]")) return;
		const rows = focusableRows();
		const current = rows.indexOf(event.target);
		if (event.key === "ArrowDown" || event.key === "ArrowUp") {
		  event.preventDefault();
		  const direction = event.key === "ArrowDown" ? 1 : -1;
		  rows[(current + direction + rows.length) % rows.length]?.focus();
		} else if (event.key === "Escape") {
		  closePopover({restoreFocus: true});
		}
	  });
	  allOptions().forEach((option) => option.addEventListener("click", () => choose(option)));
	  customEdit.addEventListener("click", openCustomDialog);
	  draftName.addEventListener("input", updateCustomDraft);
	  draftIP.addEventListener("input", updateCustomDraft);
	  applyButton.addEventListener("click", applyCustom);
	  dialog.querySelectorAll("[data-custom-cancel]").forEach((button) => {
		button.addEventListener("click", () => dialog.close());
	  });
	  dialog.addEventListener("keydown", (event) => {
		if (event.key === "Enter" && event.target.matches("input")) {
		  event.preventDefault();
		  applyCustom();
		}
	  });
	  document.addEventListener("pointerdown", (event) => {
		if (!popover.hidden && !root.contains(event.target)) closePopover();
	  });
	};

	document.querySelectorAll("[data-resolver-combobox]").forEach(setupResolverCombobox);

	const setupChartRangePicker = (popover) => {
	  if (popover.dataset.rangeReady === "true") return;
	  popover.dataset.rangeReady = "true";

	  const chart = popover.closest("#query-statistics");
	  const triggers = [...chart.querySelectorAll("[data-chart-range-open]")];
	  const form = popover.querySelector("[data-chart-range-form]");
	  const grid = popover.querySelector("[data-calendar-grid]");
	  const monthSelect = popover.querySelector("[data-calendar-month]");
	  const yearSelect = popover.querySelector("[data-calendar-year]");
	  const previous = popover.querySelector("[data-calendar-previous]");
	  const next = popover.querySelector("[data-calendar-next]");
	  const startValue = popover.querySelector("[data-chart-range-start]");
	  const endValue = popover.querySelector("[data-chart-range-end]");
	  const startTime = popover.querySelector("[data-chart-range-start-time]");
	  const endTime = popover.querySelector("[data-chart-range-end-time]");
	  const error = popover.querySelector("[data-chart-range-error]");
	  if (!chart || !form || !grid || !monthSelect || !yearSelect || !startValue || !endValue) return;

	  const pad = (value) => String(value).padStart(2, "0");
	  const dateKey = (date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
	  const parseDate = (value) => {
		const [year, month, day] = value.slice(0, 10).split("-").map(Number);
		return new Date(year, month - 1, day, 12);
	  };
	  const today = new Date();
	  const todayKey = dateKey(today);
	  const minimumYear = today.getFullYear() - 10;
	  let selectedStart = startValue.value.slice(0, 10) || dateKey(new Date(today.getTime() - 7 * 86400000));
	  let selectedEnd = endValue.value.slice(0, 10) || todayKey;
	  let cursor = parseDate(selectedStart);
	  let awaitingEnd = false;
	  const rangeWasApplied = triggers.some((trigger) => trigger.classList.contains("active"));

	  startTime.value = startValue.value.slice(11, 16) || "00:00";
	  endTime.value = endValue.value.slice(11, 16) || "00:00";
	  for (let year = minimumYear; year <= today.getFullYear(); year++) {
		const option = document.createElement("option");
		option.value = String(year);
		option.textContent = String(year);
		yearSelect.append(option);
	  }

	  const syncValues = () => {
		startValue.value = `${selectedStart}T${startTime.value || "00:00"}`;
		endValue.value = `${selectedEnd}T${endTime.value || "00:00"}`;
		error.hidden = true;
	  };

	  const validate = (showError = false) => {
		const start = new Date(startValue.value);
		const end = new Date(endValue.value);
		let message = "";
		if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
		  message = "Select both a From and To time.";
		} else if (start >= end) {
		  message = "The From time must be before the To time.";
		}
		if (showError) {
		  error.textContent = message;
		  error.hidden = !message;
		}
		return !message;
	  };

	  const updateMonthOptions = () => {
		const selectedYear = Number(yearSelect.value);
		[...monthSelect.options].forEach((option) => {
		  option.disabled = selectedYear === today.getFullYear() && Number(option.value) > today.getMonth();
		});
	  };

	  const renderCalendar = () => {
		monthSelect.value = String(cursor.getMonth());
		yearSelect.value = String(cursor.getFullYear());
		updateMonthOptions();
		previous.disabled = cursor.getFullYear() === minimumYear && cursor.getMonth() === 0;
		next.disabled = cursor.getFullYear() === today.getFullYear() && cursor.getMonth() === today.getMonth();

		const first = new Date(cursor.getFullYear(), cursor.getMonth(), 1, 12);
		const gridStart = new Date(first);
		gridStart.setDate(1 - first.getDay());
		const fragment = document.createDocumentFragment();
		for (let index = 0; index < 42; index++) {
		  const date = new Date(gridStart);
		  date.setDate(gridStart.getDate() + index);
		  const value = dateKey(date);
		  const cell = document.createElement("div");
		  const button = document.createElement("button");
		  cell.className = "calendar-day";
		  cell.setAttribute("role", "gridcell");
		  if (date.getMonth() !== cursor.getMonth()) cell.classList.add("outside-month");
		  if (value === todayKey) cell.classList.add("today");
		  if (value >= selectedStart && value <= selectedEnd) cell.classList.add("in-range");
		  if (value === selectedStart) cell.classList.add("range-start");
		  if (value === selectedEnd) cell.classList.add("range-end");
		  button.type = "button";
		  button.dataset.rangeDate = value;
		  button.textContent = String(date.getDate());
		  button.disabled = date.getFullYear() < minimumYear;
		  button.setAttribute("aria-label", date.toLocaleDateString(undefined, {year: "numeric", month: "long", day: "numeric"}));
		  button.setAttribute("aria-selected", String(value >= selectedStart && value <= selectedEnd));
		  cell.append(button);
		  fragment.append(cell);
		}
		grid.replaceChildren(fragment);
	  };

	  const open = () => {
		popover.hidden = false;
		triggers.forEach((trigger) => {
		  trigger.classList.add("picker-open");
		  trigger.setAttribute("aria-expanded", "true");
		  trigger.setAttribute("aria-pressed", "true");
		});
		renderCalendar();
	  };

	  const close = ({restoreFocus = false} = {}) => {
		popover.hidden = true;
		triggers.forEach((trigger) => {
		  trigger.classList.remove("picker-open");
		  trigger.setAttribute("aria-expanded", "false");
		  if (!rangeWasApplied) trigger.setAttribute("aria-pressed", "false");
		});
		if (restoreFocus) triggers.find((trigger) => trigger.offsetParent !== null)?.focus();
	  };

	  triggers.forEach((trigger) => trigger.addEventListener("click", () => {
		if (popover.hidden) open(); else close({restoreFocus: true});
	  }));
	  previous.addEventListener("click", () => {
		cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1, 12);
		renderCalendar();
	  });
	  next.addEventListener("click", () => {
		cursor = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1, 12);
		renderCalendar();
	  });
	  monthSelect.addEventListener("change", () => {
		cursor = new Date(Number(yearSelect.value), Number(monthSelect.value), 1, 12);
		renderCalendar();
	  });
	  yearSelect.addEventListener("change", () => {
		const month = Number(yearSelect.value) === today.getFullYear()
		  ? Math.min(Number(monthSelect.value), today.getMonth())
		  : Number(monthSelect.value);
		cursor = new Date(Number(yearSelect.value), month, 1, 12);
		renderCalendar();
	  });
	  grid.addEventListener("click", (event) => {
		const button = event.target.closest("[data-range-date]");
		if (!button || button.disabled) return;
		const value = button.dataset.rangeDate;
		if (!awaitingEnd) {
		  selectedStart = value;
		  selectedEnd = value;
		  awaitingEnd = true;
		} else {
		  const previousStart = selectedStart;
		  selectedStart = value < previousStart ? value : previousStart;
		  selectedEnd = value < previousStart ? previousStart : value;
		  awaitingEnd = false;
		}
		cursor = parseDate(value);
		syncValues();
		renderCalendar();
	  });
	  startTime.addEventListener("input", syncValues);
	  endTime.addEventListener("input", syncValues);
	  form.addEventListener("htmx:beforeRequest", (event) => {
		if (!validate(true)) event.preventDefault();
	  });
	  document.addEventListener("pointerdown", (event) => {
		if (!popover.hidden && !popover.contains(event.target) && !triggers.some((trigger) => trigger.contains(event.target))) close();
	  });
	  document.addEventListener("keydown", (event) => {
		if (event.key === "Escape" && !popover.hidden) close({restoreFocus: true});
	  });
	  syncValues();
	};

	const setupToast = (toast) => {
	  if (toast.dataset.toastReady === "true") return;
	  toast.dataset.toastReady = "true";

	  const duration = Number(toast.dataset.toastDuration) || 4500;
	  toast.style.setProperty("--toast-duration", `${duration}ms`);
	  let remaining = duration;
	  let startedAt = 0;
	  let timeoutID;

	  const remove = () => {
		const region = toast.closest(".toast-region");
		toast.remove();
		if (region && !region.querySelector("[data-toast]")) region.remove();
	  };
	  const dismiss = () => {
		if (toast.classList.contains("is-leaving")) return;
		window.clearTimeout(timeoutID);
		toast.classList.add("is-leaving");
		window.setTimeout(remove, 160);
	  };
	  const schedule = () => {
		startedAt = Date.now();
		timeoutID = window.setTimeout(dismiss, remaining);
	  };

	  toast.querySelector("[data-toast-close]")?.addEventListener("click", dismiss);
	  toast.addEventListener("pointerenter", () => {
		remaining = Math.max(0, remaining - (Date.now() - startedAt));
		window.clearTimeout(timeoutID);
		toast.classList.add("is-paused");
	  });
	  toast.addEventListener("pointerleave", () => {
		toast.classList.remove("is-paused");
		schedule();
	  });
	  schedule();
	};

	const syncDNSSECDenial = (select) => {
	  const section = select.closest("form")?.querySelector("[data-dnssec-nsec3]");
	  if (!section) return;
	  const shown = select.value === "nsec3";
	  section.hidden = !shown;
	  section.querySelectorAll("input, select, textarea").forEach((field) => { field.disabled = !shown; });
	};

	const setupIsotopeTabs = (root) => {
	  if (!root || root.dataset.isotopeTabsReady === "true") return;
	  root.dataset.isotopeTabsReady = "true";
	  const tabs = [...root.querySelectorAll(":scope > [role=tablist] [data-isotope-tab]")];
	  const panels = [...root.querySelectorAll(":scope > [data-isotope-panel], :scope > form > [data-isotope-panel]")];
	  const select = (value, updateURL = true) => {
		const selected = tabs.find((tab) => tab.dataset.isotopeTab === value && !tab.disabled);
		if (!selected) return;
		tabs.forEach((tab) => {
		  const active = tab === selected;
		  tab.classList.toggle("active", active);
		  tab.setAttribute("aria-selected", String(active));
		  tab.tabIndex = active ? 0 : -1;
		});
		panels.forEach((panel) => { panel.hidden = panel.dataset.isotopePanel !== value; });
		root.dataset.activeTab = value;
		if (updateURL) {
		  const url = new URL(window.location.href);
		  const parameter = root.dataset.tabParam || "tab";
		  if (value === tabs.find((tab) => !tab.disabled)?.dataset.isotopeTab) url.searchParams.delete(parameter);
		  else url.searchParams.set(parameter, value);
		  window.history.replaceState(window.history.state, "", url);
		}
	  };
	  tabs.forEach((tab, index) => {
		tab.addEventListener("click", () => select(tab.dataset.isotopeTab));
		tab.addEventListener("keydown", (event) => {
		  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
		  event.preventDefault();
		  const enabled = tabs.filter((candidate) => !candidate.disabled);
		  const current = enabled.indexOf(tab);
		  const direction = event.key === "ArrowRight" ? 1 : -1;
		  const next = enabled[(current + direction + enabled.length) % enabled.length];
		  next.focus();
		  select(next.dataset.isotopeTab);
		});
	  });
	  select(root.dataset.activeTab || tabs.find((tab) => !tab.disabled)?.dataset.isotopeTab, false);
	};

	const setupCertificateSettings = (root) => {
	  if (!root || root.dataset.certificateReady === "true") return;
	  root.dataset.certificateReady = "true";
	  const modeInputs = [...root.querySelectorAll('input[name="certificate_mode"]')];
	  const manual = root.querySelector("[data-certificate-manual]");
	  const acme = root.querySelector("[data-certificate-acme]");
	  const syncMode = () => {
		const managed = modeInputs.find((input) => input.checked)?.value === "acme";
		if (manual) manual.hidden = managed;
		if (acme) acme.hidden = !managed;
		modeInputs.forEach((input) => input.closest("label")?.classList.toggle("active", input.checked));
	  };
	  modeInputs.forEach((input) => input.addEventListener("change", syncMode));
	  const provider = root.querySelector("[data-acme-provider]");
	  const syncProvider = () => {
		root.querySelectorAll("[data-acme-credentials]").forEach((fields) => {
		  fields.hidden = fields.dataset.acmeCredentials !== provider?.value;
		});
	  };
	  provider?.addEventListener("change", syncProvider);
	  syncMode();
	  syncProvider();
	};

	// The UniFi setup wizard runs server-side because each step needs live data
	// from the controller. These handlers only cover what does not need a round
	// trip: which credential fields are relevant, and the sample name a template
	// produces.
	const setupUniFiAuthModes = (root) => {
	  if (!root || root.dataset.unifiAuthReady === "true") return;
	  root.dataset.unifiAuthReady = "true";
	  const form = root.closest("form") || root;
	  const modes = [...root.querySelectorAll("[data-unifi-auth]")];
	  const syncMode = () => {
		const mode = modes.find((input) => input.checked)?.value || "api-key";
		modes.forEach((input) => input.closest("label")?.classList.toggle("active", input.checked));
		form.querySelectorAll("[data-unifi-auth-panel]").forEach((panel) => {
		  panel.hidden = panel.dataset.unifiAuthPanel !== mode;
		});
	  };
	  modes.forEach((input) => input.addEventListener("change", syncMode));
	  syncMode();
	};

	const setupUniFiZoneRows = (root) => {
	  if (!root || root.dataset.unifiZoneRowsReady === "true") return;
	  root.dataset.unifiZoneRowsReady = "true";
	  root.querySelectorAll("[data-unifi-zone-row]").forEach((row) => {
		const zone = row.querySelector("[data-unifi-zone]");
		const template = row.querySelector("[data-unifi-template]");
		const preview = row.querySelector(".unifi-zone-preview");
		const network = row.querySelector('input[name^="network_name_"]')?.value || "";
		const slug = (value) => value.toLowerCase().replace(/['\u2018\u2019]/g, "").replace(/[\s_.]+/g, "-").replace(/[^a-z0-9-]/g, "").replace(/-+/g, "-").replace(/^-|-$/g, "");
		const syncPreview = () => {
		  const zoneName = zone?.value.trim().replace(/^\.+|\.+$/g, "").toLowerCase() || "";
		  if (!preview || !zoneName) return;
		  const parts = template?.value === "{{host}}.{{zone}}"
			? ["macbook-pro", zoneName]
			: ["macbook-pro", slug(network), zoneName].filter(Boolean);
		  preview.innerHTML = "";
		  preview.append("Example: ");
		  const code = document.createElement("code");
		  code.textContent = parts.join(".");
		  preview.append(code);
		};
		zone?.addEventListener("input", syncPreview);
		template?.addEventListener("change", syncPreview);
		syncPreview();
	  });
	};

	const setupClusterOnboarding = (root) => {
	  if (!root || root.dataset.clusterOnboardingReady === "true") return;
	  root.dataset.clusterOnboardingReady = "true";
	  let step = Number(root.dataset.initialStep) === 2 ? 2 : 1;
	  const panels = [...root.querySelectorAll("[data-cluster-wizard-panel]")];
	  const progressSteps = [...root.querySelectorAll(".cluster-wizard-progress > div")];
	  const next = root.querySelector("[data-cluster-wizard-next]");
	  const back = root.querySelector("[data-cluster-wizard-back]");
	  const cancel = root.querySelector("[data-cluster-wizard-cancel]");
	  const submit = root.querySelector("[data-cluster-wizard-submit]");
	  const sources = [...root.querySelectorAll('input[name="certificate_source"]')];
	  const provider = root.querySelector("[data-acme-provider]");
	  const advertisedURL = root.querySelector("[data-https-url]");
	  const validateAdvertisedURL = () => {
		if (!advertisedURL) return;
		const value = advertisedURL.value.trim();
		let message = "";
		if (value !== "") {
		  try {
			const parsed = new URL(value);
			if (parsed.protocol !== "https:" || !parsed.host || parsed.username || parsed.password || parsed.search || parsed.hash) {
			  message = "Enter an absolute HTTPS URL without credentials, query, or fragment.";
			}
		  } catch {
			message = "Enter an absolute HTTPS URL such as https://dns-1.example.com:5443.";
		  }
		}
		advertisedURL.setCustomValidity(message);
	  };
	  const syncCertificate = () => {
		const source = sources.find((input) => input.checked)?.value || "external";
		root.querySelectorAll("[data-cluster-certificate-panel]").forEach((panel) => {
		  panel.hidden = panel.dataset.clusterCertificatePanel !== source;
		});
		sources.forEach((input) => input.closest("label")?.classList.toggle("active", input.checked));
		root.querySelectorAll("[data-acme-credentials]").forEach((fields) => {
		  fields.hidden = source !== "acme" || fields.dataset.acmeCredentials !== provider?.value;
		});
		const requiredNames = source === "acme"
		  ? ["https_listen", "acme_email", "acme_domains", "acme_dns_provider", "acme_storage_dir"]
		  : source === "generated"
			? ["generated_https_listen", "generated_valid_days", "generated_storage_dir"]
		  : source === "import"
			? ["import_https_listen", "manual_import_storage_dir", "manual_certificate_pem", "manual_private_key_pem"]
			: [];
		root.querySelectorAll("[data-cluster-certificate-panel] [name]").forEach((input) => {
		  input.required = requiredNames.includes(input.name);
		});
	  };
	  const syncStep = () => {
		panels.forEach((panel) => { panel.hidden = Number(panel.dataset.clusterWizardPanel) !== step; });
		progressSteps.forEach((item, index) => {
		  const itemStep = index + 1;
		  item.classList.toggle("current", itemStep === step);
		  item.classList.toggle("complete", itemStep < step);
		  const marker = item.querySelector("span");
		  if (marker && itemStep <= 2) marker.textContent = itemStep < step ? "✓" : String(itemStep);
		});
		if (next) next.hidden = step !== 1;
		if (submit) submit.hidden = step !== 2;
		if (back) back.hidden = step !== 2;
		if (cancel) cancel.hidden = step !== 1;
		root.querySelector(".isotope-dialog-body")?.scrollTo({top: 0});
	  };
	  const validateStep = () => {
		const panel = panels.find((candidate) => Number(candidate.dataset.clusterWizardPanel) === step);
		const invalid = [...(panel?.querySelectorAll("input, select, textarea") || [])].find((input) => !input.checkValidity());
		if (!invalid) return true;
		if (invalid.closest("details")) invalid.closest("details").open = true;
		invalid.reportValidity();
		return false;
	  };
	  next?.addEventListener("click", () => {
		if (!validateStep()) return;
		step = 2;
		syncStep();
	  });
	  back?.addEventListener("click", () => {
		step = 1;
		syncStep();
	  });
	  sources.forEach((input) => input.addEventListener("change", syncCertificate));
	  provider?.addEventListener("change", syncCertificate);
	  advertisedURL?.addEventListener("input", validateAdvertisedURL);
	  advertisedURL?.addEventListener("change", validateAdvertisedURL);
	  validateAdvertisedURL();
	  syncCertificate();
	  syncStep();
	};

	// Shared confirmation dialog. htmx actions reach it through hx-confirm, and
	// the managed restart button calls it directly because it issues its own
	// request instead of an htmx one.
	const confirmAction = (question, options = {}) =>
	  new Promise((resolve) => {
		const dialog = document.createElement("dialog");
		dialog.className = "custom-server-dialog confirmation-dialog";
		dialog.innerHTML = `<div class="dialog-header"><h2></h2><p></p></div><footer class="dialog-footer"><button class="button outline" type="button" data-confirm-cancel>Cancel</button><button class="button" type="button" data-confirm-accept></button></footer>`;
		dialog.querySelector("h2").textContent = options.title || "Confirm action";
		dialog.querySelector("p").textContent = question;
		const accept = dialog.querySelector("[data-confirm-accept]");
		// Red is reserved for actions that destroy or interrupt something.
		if (options.tone !== "neutral") accept.classList.add("destructive");
		accept.textContent = options.action || "Continue";
		let accepted = false;
		dialog.addEventListener("close", () => {
		  dialog.remove();
		  resolve(accepted);
		}, {once: true});
		dialog.querySelector("[data-confirm-cancel]").addEventListener("click", () => dialog.close());
		accept.addEventListener("click", () => {
		  accepted = true;
		  dialog.close();
		});
		document.body.append(dialog);
		dialog.showModal();
		dialog.querySelector("[data-confirm-cancel]").focus();
	  });

	const setupManagedRestart = (root) => {
	  if (!root || root.dataset.sableRestartReady === "true") return;
	  root.dataset.sableRestartReady = "true";
	  const button = root.querySelector("[data-sable-restart-button]");
	  const buttonLabel = button?.querySelector("span");
	  const status = root.querySelector("[data-restart-status]");
	  const exit = root.querySelector("[data-restart-exit]");
	  const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));
	  let previousInstance = "";
	  const fetchHealth = async () => {
		const controller = new AbortController();
		const timeout = window.setTimeout(() => controller.abort(), 2500);
		try {
		  return await fetch(root.dataset.healthUrl, {cache: "no-store", signal: controller.signal});
		} finally {
		  window.clearTimeout(timeout);
		}
	  };

	  const showFailure = (message) => {
		root.classList.remove("is-restarting");
		if (status) status.textContent = message;
		if (button) button.disabled = false;
		if (buttonLabel) buttonLabel.textContent = "Check Again";
	  };

	  const waitForSable = async () => {
		const deadline = Date.now() + 120000;
		let stopped = false;
		while (Date.now() < deadline) {
		  try {
			const response = await fetchHealth();
			if (response.ok) {
			  const health = await response.json();
			  if (health.instance_id && health.instance_id !== previousInstance) {
				if (status) status.textContent = "Sable is back online. Continuing setup…";
				window.location.assign(root.dataset.continueUrl);
				return;
			  }
			  if (stopped && !health.instance_id) {
				window.location.assign(root.dataset.continueUrl);
				return;
			  }
			}
		  } catch {
			stopped = true;
			if (status) status.textContent = "Sable has stopped. Waiting for the service manager to bring it back online…";
		  }
		  await sleep(1000);
		}
		showFailure("Sable has not come back online. Check the Docker or service restart policy, then try again.");
	  };

	  button?.addEventListener("click", async () => {
		if (!previousInstance && root.dataset.restartConfirm) {
		  const accepted = await confirmAction(root.dataset.restartConfirm, {
			title: root.dataset.restartConfirmTitle || "Restart Sable?",
			action: root.dataset.restartConfirmAction || "Restart",
		  });
		  if (!accepted) return;
		}
		if (previousInstance) {
		  button.disabled = true;
		  root.classList.add("is-restarting");
		  if (buttonLabel) buttonLabel.textContent = "Checking…";
		  await waitForSable();
		  return;
		}
		button.disabled = true;
		exit?.setAttribute("aria-disabled", "true");
		root.classList.add("is-restarting");
		if (buttonLabel) buttonLabel.textContent = "Restarting…";
		if (status) status.textContent = "Finishing active requests and shutting down cleanly…";
		try {
		  const health = await fetchHealth();
		  if (!health.ok) throw new Error("Sable health check failed before restart.");
		  const current = await health.json();
		  previousInstance = current.instance_id || "unknown";
		  const response = await fetch(root.dataset.restartUrl, {
			method: "POST",
			cache: "no-store",
			headers: {"Accept": "application/json", "X-CSRF-Token": root.dataset.csrfToken || ""},
		  });
		  const result = await response.json().catch(() => ({}));
		  if (!response.ok) {
			previousInstance = "";
			throw new Error(result.error || `Restart request failed (${response.status})`);
		  }
		  previousInstance = result.instance_id || previousInstance;
		  await waitForSable();
		} catch (error) {
		  if (previousInstance) {
			await waitForSable();
		  } else {
			showFailure(error?.message || "Sable could not start a controlled restart.");
		  }
		}
	  });
	};

	const setupDialogTabs = (root) => {
	  if (!root?.matches?.("[data-dialog-tabs]") || root.dataset.dialogTabsReady === "true") return;
	  root.dataset.dialogTabsReady = "true";
	  const tabs = [...root.querySelectorAll("[data-dialog-tab]")];
	  const panels = [...root.querySelectorAll("[data-dialog-panel]")];
	  const select = (value, focus = false) => {
		const selected = tabs.find((tab) => tab.dataset.dialogTab === value);
		if (!selected) return;
		tabs.forEach((tab) => {
		  const active = tab === selected;
		  tab.classList.toggle("active", active);
		  tab.setAttribute("aria-selected", String(active));
		  tab.tabIndex = active ? 0 : -1;
		});
		panels.forEach((panel) => { panel.hidden = panel.dataset.dialogPanel !== value; });
		root.querySelectorAll("[data-dialog-save]").forEach((button) => { button.hidden = button.dataset.dialogSave !== value; });
		panels.find((panel) => panel.dataset.dialogPanel === value)?.dispatchEvent(new Event("dialogTabShown", {bubbles: true}));
		if (focus) selected.focus();
	  };
	  tabs.forEach((tab) => {
		tab.addEventListener("click", () => select(tab.dataset.dialogTab));
		tab.addEventListener("keydown", (event) => {
		  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
		  event.preventDefault();
		  const current = tabs.indexOf(tab);
		  const direction = event.key === "ArrowRight" ? 1 : -1;
		  select(tabs[(current + direction + tabs.length) % tabs.length].dataset.dialogTab, true);
		});
	  });
	  root.sableResetDialogTabs = () => select(tabs[0]?.dataset.dialogTab);
	  root.sableSelectDialogTab = select;
	  root.querySelectorAll("form").forEach((form) => {
		form.addEventListener("invalid", (event) => {
		  const panel = event.target.closest?.("[data-dialog-panel]");
		  if (panel?.dataset.dialogPanel) select(panel.dataset.dialogPanel);
		}, true);
	  });
	  root.sableResetDialogTabs();
	};

	const setupClusterTLSAccordion = (root) => {
	  if (!root || root.dataset.clusterTlsReady === "true") return;
	  root.dataset.clusterTlsReady = "true";
	  const scope = root.closest(".cluster-settings-dialog") || root;
	  const choices = [...root.querySelectorAll("[data-cluster-tls-option]")];
	  let scheduled = false;
	  const sync = () => {
		scheduled = false;
		let selected = choices.find((choice) => choice.open);
		if (!selected) {
		  selected = choices[0];
		  if (selected) selected.open = true;
		}
		choices.forEach((choice) => {
		  if (choice !== selected && choice.open) choice.open = false;
		});
		const value = selected?.dataset.clusterTlsOption || "generate";
		scope.querySelectorAll("[data-cluster-tls-action]").forEach((action) => {
		  action.hidden = action.dataset.clusterTlsAction !== value;
		});
	  };
	  choices.forEach((choice) => choice.addEventListener("toggle", () => {
		if (scheduled) return;
		scheduled = true;
		queueMicrotask(sync);
	  }));
	  sync();
	};

	const setupCreateUserForm = (form) => {
	  if (!form || form.dataset.userValidationReady === "true") return;
	  form.dataset.userValidationReady = "true";
	  const dialog = form.closest("#create-user-dialog");
	  const username = form.querySelector("[data-user-username]");
	  const usernameError = form.querySelector("[data-username-error]");
	  const roles = [...form.querySelectorAll('input[name="roles"]')];
	  const groupFieldset = form.querySelector("[data-group-fieldset]");
	  const groupError = form.querySelector("[data-group-error]");
	  const groupStatus = form.querySelector("[data-group-access-status]");
	  const passwordFields = form.querySelector("[data-web-access-passwords]");
	  const password = form.querySelector("[data-user-password]");
	  const confirmation = form.querySelector("[data-user-password-confirm]");
	  const passwordError = form.querySelector("[data-password-error]");

	  const usernameMessage = () => {
		const value = username.value.trim();
		if (!value) return "Enter a username.";
		if (value.length < 3 || value.length > 64) return "Username must contain 3 to 64 characters.";
		if (!/^[a-z0-9._-]+$/.test(value)) return "Use lowercase letters, numbers, dots, underscores, or hyphens only.";
		return "";
	  };
	  const validateUsername = (show = false) => {
		const message = usernameMessage();
		username.setCustomValidity(message);
		username.toggleAttribute("aria-invalid", Boolean(message) && show);
		if (usernameError) {
		  usernameError.textContent = message;
		  usernameError.hidden = !message || !show;
		}
		return !message;
	  };
	  const updatePasswordValidation = (show = false) => {
		if (password.disabled) {
		  password.setCustomValidity("");
		  confirmation.setCustomValidity("");
		  if (passwordError) passwordError.hidden = true;
		  return true;
		}
		let message = "";
		if (password.value.length < 12) message = "Enter a password containing at least 12 characters.";
		else if (confirmation.value !== password.value) message = "Password confirmation does not match.";
		password.setCustomValidity(password.value.length < 12 ? message : "");
		confirmation.setCustomValidity(password.value.length >= 12 && confirmation.value !== password.value ? message : "");
		password.toggleAttribute("aria-invalid", Boolean(message) && show);
		confirmation.toggleAttribute("aria-invalid", Boolean(message) && show);
		if (passwordError) {
		  passwordError.textContent = message;
		  passwordError.hidden = !message || !show;
		}
		return !message;
	  };
	  const updateGroups = (showError = false) => {
		const selected = roles.filter((role) => role.checked);
		const hasWebAccess = selected.some((role) => role.dataset.roleWeb === "true");
		passwordFields.hidden = !hasWebAccess;
		passwordFields.querySelectorAll("input").forEach((input) => {
		  input.disabled = !hasWebAccess;
		  input.required = hasWebAccess;
		  if (!hasWebAccess) input.value = "";
		});
		if (groupStatus) {
		  groupStatus.classList.toggle("api-only", selected.length > 0 && !hasWebAccess);
		  groupStatus.classList.toggle("web-enabled", hasWebAccess);
		  if (selected.length === 0) groupStatus.innerHTML = "<strong>Select at least one group</strong><span>Password requirements depend on the selected group permissions.</span>";
		  else if (hasWebAccess) groupStatus.innerHTML = "<strong>Web UI access enabled</strong><span>The selected groups grant console access, so a password is required.</span>";
		  else groupStatus.innerHTML = "<strong>API-only identity</strong><span>The selected groups have no Web UI grants, so no password is required.</span>";
		}
		const missing = selected.length === 0;
		groupFieldset?.classList.toggle("invalid", missing && showError);
		if (groupError) groupError.hidden = !missing || !showError;
		if (!hasWebAccess) updatePasswordValidation(false);
		return !missing;
	  };

	  username.addEventListener("input", () => validateUsername(false));
	  username.addEventListener("blur", () => validateUsername(true));
	  username.addEventListener("invalid", () => validateUsername(true));
	  roles.forEach((role) => role.addEventListener("change", () => updateGroups(false)));
	  password.addEventListener("input", () => updatePasswordValidation(false));
	  confirmation.addEventListener("input", () => updatePasswordValidation(false));
	  password.addEventListener("blur", () => updatePasswordValidation(true));
	  confirmation.addEventListener("blur", () => updatePasswordValidation(true));
	  password.addEventListener("invalid", () => updatePasswordValidation(true));
	  confirmation.addEventListener("invalid", () => updatePasswordValidation(true));
	  form.addEventListener("submit", (event) => {
		const usernameValid = validateUsername(true);
		const groupsValid = updateGroups(true);
		const passwordValid = updatePasswordValidation(true);
		if (!groupsValid) {
		  event.preventDefault();
		  event.stopImmediatePropagation();
		  dialog?.sableSelectDialogTab?.("groups");
		  roles[0]?.focus();
		  return;
		}
		if (!usernameValid || !passwordValid || !form.checkValidity()) {
		  event.preventDefault();
		  event.stopImmediatePropagation();
		  dialog?.sableSelectDialogTab?.("info");
		  form.querySelector(":invalid")?.focus();
		  form.reportValidity();
		}
	  }, true);
	  validateUsername(false);
	  updateGroups(false);
	};

	let queryResultSearch = "";
	const setupLogLivePanel = (panel) => {
	  if (!panel || panel.dataset.logLiveReady === "true") return;
	  panel.dataset.logLiveReady = "true";
	  let timer = null;
	  let requestInFlight = false;
	  const button = panel.querySelector("[data-log-live-toggle]");
	  const input = panel.querySelector("[data-log-live-input]");
	  const label = button?.querySelector("span");
	  const filtersButton = panel.querySelector("[data-query-filters-toggle]");
	  const filtersPanel = panel.querySelector("[data-query-filters]");
	  const stop = () => {
		if (timer !== null) window.clearInterval(timer);
		timer = null;
	  };
	  const poll = () => {
		if (!document.contains(panel)) { stop(); return; }
		if (document.hidden || requestInFlight || panel.dataset.live !== "true") return;
		requestInFlight = true;
		htmx.ajax("GET", panel.dataset.liveUrl, {target: `#${panel.id}`, swap: "outerHTML"})
		  .finally?.(() => { requestInFlight = false; });
	  };
	  const start = () => {
		stop();
		if (panel.dataset.live !== "true") return;
		timer = window.setInterval(poll, 3000);
	  };
	  button?.addEventListener("click", () => {
		const live = panel.dataset.live !== "true";
		panel.dataset.live = String(live);
		button.classList.toggle("active", live);
		button.setAttribute("aria-pressed", String(live));
		if (label) label.textContent = live ? "Pause" : "Live";
		if (input) input.value = live ? "1" : "0";
		if (live) { poll(); start(); } else stop();
	  });
	  filtersButton?.addEventListener("click", () => {
		const open = filtersPanel?.hasAttribute("hidden");
		if (open) filtersPanel?.removeAttribute("hidden");
		else filtersPanel?.setAttribute("hidden", "");
		filtersButton.classList.toggle("active", open);
		filtersButton.setAttribute("aria-expanded", String(open));
		const liveURL = new URL(panel.dataset.liveUrl, window.location.origin);
		if (open) liveURL.searchParams.set("filters", "1");
		else liveURL.searchParams.delete("filters");
		panel.dataset.liveUrl = liveURL.pathname + liveURL.search;
	  });
	  const resultSearch = panel.querySelector("[data-query-result-search]");
	  if (resultSearch) resultSearch.value = queryResultSearch;
	  const applyResultSearch = (search) => {
		panel.querySelectorAll("[data-query-result-row]").forEach((row) => {
		  row.hidden = search !== "" && !row.textContent.toLowerCase().includes(search);
		});
	  };
	  applyResultSearch(queryResultSearch);
	  resultSearch?.addEventListener("input", (event) => {
		const search = event.target.value.trim().toLowerCase();
		queryResultSearch = search;
		applyResultSearch(search);
	  });
	  panel.querySelector("[data-query-page-size]")?.addEventListener("change", (event) => {
		const target = new URL(panel.dataset.liveUrl, window.location.origin);
		target.searchParams.set("page", "1");
		target.searchParams.set("page_size", event.target.value);
		if (panel.dataset.live !== "true") target.searchParams.delete("live");
		htmx.ajax("GET", target.pathname + target.search, {target: `#${panel.id}`, swap: "outerHTML"});
	  });
	  start();
	};

	const initializeSwappedContent = (root) => {
	  if (!root) return;
	  setupReplicaReadOnly(root);
	  if (root.matches?.("[data-chart-range-popover]")) setupChartRangePicker(root);
	  root.querySelectorAll?.("[data-chart-range-popover]").forEach(setupChartRangePicker);
	  if (root.matches?.("[data-toast]")) setupToast(root);
	  root.querySelectorAll?.("[data-toast]").forEach(setupToast);
	  if (root.matches?.("[data-dnssec-denial]")) syncDNSSECDenial(root);
	  root.querySelectorAll?.("[data-dnssec-denial]").forEach(syncDNSSECDenial);
	  if (root.matches?.("[data-isotope-tabs]")) setupIsotopeTabs(root);
	  root.querySelectorAll?.("[data-isotope-tabs]").forEach(setupIsotopeTabs);
	  if (root.matches?.("[data-certificate-settings]")) setupCertificateSettings(root);
	  root.querySelectorAll?.("[data-certificate-settings]").forEach(setupCertificateSettings);
	  if (root.matches?.("[data-cluster-onboarding]")) setupClusterOnboarding(root);
	  root.querySelectorAll?.("[data-cluster-onboarding]").forEach(setupClusterOnboarding);
	  if (root.matches?.("[data-sable-restart]")) setupManagedRestart(root);
	  root.querySelectorAll?.("[data-sable-restart]").forEach(setupManagedRestart);
	  if (root.matches?.("[data-dialog-tabs]")) setupDialogTabs(root);
	  root.querySelectorAll?.("[data-dialog-tabs]").forEach(setupDialogTabs);
	  if (root.matches?.("[data-cluster-tls-accordion]")) setupClusterTLSAccordion(root);
	  root.querySelectorAll?.("[data-cluster-tls-accordion]").forEach(setupClusterTLSAccordion);
	  if (root.matches?.("[data-create-user-form]")) setupCreateUserForm(root);
	  root.querySelectorAll?.("[data-create-user-form]").forEach(setupCreateUserForm);
	  if (root.matches?.("[data-unifi-auth-root]")) setupUniFiAuthModes(root);
	  root.querySelectorAll?.("[data-unifi-auth-root]").forEach(setupUniFiAuthModes);
	  if (root.matches?.("[data-unifi-zone-rows]")) setupUniFiZoneRows(root);
	  root.querySelectorAll?.("[data-unifi-zone-rows]").forEach(setupUniFiZoneRows);
	  if (root.matches?.("[data-log-live-panel]")) setupLogLivePanel(root);
	  root.querySelectorAll?.("[data-log-live-panel]").forEach(setupLogLivePanel);
	};

	initializeSwappedContent(document);
	document.body.addEventListener("htmx:afterSwap", (event) => {
	  initializeSwappedContent(event.detail?.target);
	  if (event.detail?.target?.id === "api-token-result" && event.detail.target.querySelector(".token-created")) {
		const dialog = event.detail.target.closest("#create-token-dialog");
		dialog?.querySelector("[data-token-fields]")?.setAttribute("hidden", "");
		dialog?.querySelector("[data-token-submit]")?.setAttribute("hidden", "");
		const close = dialog?.querySelector("[data-token-close]");
		if (close) close.textContent = "Close";
		dialog?.setAttribute("data-token-created", "true");
	  }
	});
	document.body.addEventListener("htmx:load", (event) => {
	  initializeSwappedContent(event.detail?.elt);
	});

	document.addEventListener("click", (event) => {
	  const button = event.target.closest?.("[data-permission-select]");
	  if (!button) return;
	  const surface = button.closest(".permission-surface");
	  if (!surface) return;
	  const checked = button.dataset.permissionSelect === "all";
	  surface.querySelectorAll('.permission-checks input[type="checkbox"]:not(:disabled)').forEach((input) => {
		input.checked = checked;
	  });
	});

	document.addEventListener("change", (event) => {
	  const owner = event.target.closest?.("[data-token-owner]");
	  if (!owner) return;
	  const dialog = owner.closest("#create-token-dialog");
	  dialog?.querySelectorAll("[data-token-group-users]").forEach((input) => {
		const assigned = input.dataset.tokenGroupUsers.split(",").filter(Boolean).includes(owner.value);
		input.disabled = !assigned;
		if (!assigned) input.checked = false;
		const label = input.closest("label");
		if (label) label.hidden = !assigned;
	  });
	  const submit = dialog?.querySelector("[data-token-submit]");
	  if (submit) submit.disabled = document.body.dataset.controlPlaneReadOnly === "true" || !dialog.querySelector('input[name="groups"]:checked:not(:disabled)');
	});

	document.addEventListener("change", (event) => {
	  if (!event.target.matches?.('#create-token-dialog input[name="groups"]')) return;
	  const dialog = event.target.closest("#create-token-dialog");
	  const submit = dialog?.querySelector("[data-token-submit]");
	  if (submit) submit.disabled = document.body.dataset.controlPlaneReadOnly === "true" || !dialog.querySelector('input[name="groups"]:checked:not(:disabled)');
	});


	const queryName = document.querySelector("[data-query-name]");
	const queryClear = document.querySelector("[data-query-clear]");
	const quickQueryDescription = document.querySelector("[data-quick-query-description]");
	const updateQueryContext = () => {
	  if (!queryName) return;
	  const domain = queryName.value.trim();
	  if (queryClear) queryClear.hidden = !domain;
	  if (quickQueryDescription) {
		quickQueryDescription.textContent = domain
		  ? `Query ${domain} for:`
		  : "Enter a domain, then select a query type";
	  }
	};

	const selectRecordType = (form, recordType) => {
	  if (!form || !recordType) return;
	  const value = form.querySelector("[data-record-type-value]");
	  const description = form.querySelector("[data-record-type-description]");
	  const more = form.querySelector("[data-record-more-types]");
	  const selectedButton = form.querySelector(`[data-record-type-choice="${CSS.escape(recordType)}"]`);
	  if (value) value.value = recordType;
	  form.querySelectorAll("[data-record-type-choice]").forEach((button) => {
		const active = button.dataset.recordTypeChoice === recordType;
		button.classList.toggle("active", active);
		button.setAttribute("aria-pressed", String(active));
	  });
	  if (more) more.value = selectedButton ? "" : recordType;
	  if (description) {
		description.textContent = selectedButton?.dataset.recordDescription || more?.selectedOptions?.[0]?.dataset.description || "";
	  }
	  form.querySelectorAll("[data-record-fields]").forEach((panel) => {
		const active = panel.dataset.recordFields === recordType;
		panel.hidden = !active;
		panel.querySelectorAll("input, select, textarea").forEach((field) => { field.disabled = !active; });
	  });
	  const comments = form.querySelector("[data-record-comments]");
	  if (comments) {
		comments.hidden = recordType === "NS";
		comments.querySelector("input")?.toggleAttribute("disabled", recordType === "NS");
	  }
	};
	queryName?.addEventListener("input", updateQueryContext);
	queryClear?.addEventListener("click", () => {
	  queryName.value = "";
	  queryName.focus();
	  updateQueryContext();
	});
	updateQueryContext();

	  const applyTheme = (theme) => {
		const selected = ["light", "dark"].includes(theme) ? theme : "system";
		localStorage.setItem(themeKey, selected);
		document.documentElement.classList.toggle("dark", selected === "dark" || (selected === "system" && systemDark()));
		document.querySelectorAll("[data-theme-value]").forEach((button) => {
		  const active = button.dataset.themeValue === selected;
		  button.classList.toggle("active", active);
		  button.setAttribute("aria-checked", String(active));
		});
	  };
	  document.querySelectorAll("[data-theme-value]").forEach((button) => {
		button.addEventListener("click", () => applyTheme(button.dataset.themeValue));
	  });
	  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
		if (currentTheme() === "system") applyTheme("system");
	  });
	  applyTheme(currentTheme());

	  const closeAccountMenus = (except = null) => {
		document.querySelectorAll("[data-account-menu]").forEach((menu) => {
		  if (menu === except) return;
		  menu.querySelector("[data-account-popover]")?.setAttribute("hidden", "");
		  menu.querySelector("[data-account-trigger]")?.setAttribute("aria-expanded", "false");
		});
	  };
	  document.querySelectorAll("[data-account-menu]").forEach((menu) => {
		const trigger = menu.querySelector("[data-account-trigger]");
		const popover = menu.querySelector("[data-account-popover]");
		if (!trigger || !popover) return;
		trigger.addEventListener("click", (event) => {
		  event.stopPropagation();
		  const opening = popover.hasAttribute("hidden");
		  closeAccountMenus(opening ? menu : null);
		  popover.toggleAttribute("hidden", !opening);
		  trigger.setAttribute("aria-expanded", String(opening));
		});
		popover.addEventListener("click", (event) => event.stopPropagation());
	  });
	  document.addEventListener("click", () => closeAccountMenus());
	  document.addEventListener("keydown", (event) => {
		if (event.key === "Escape") closeAccountMenus();
	  });

	const syncSidebarToggleState = () => {
	  const collapsed = document.documentElement.classList.contains("sidebar-collapsed");
	  document.querySelectorAll(".sidebar-collapse, .sidebar-rail").forEach((button) => {
		const label = collapsed ? "Expand sidebar" : "Collapse sidebar";
		button.setAttribute("aria-label", label);
		button.title = label;
	  });
	};
	syncSidebarToggleState();
	  document.querySelectorAll("[data-sidebar-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        if (window.matchMedia("(max-width: 767px)").matches) {
          document.documentElement.classList.toggle("sidebar-mobile-open");
          return;
        }
        const collapsed = document.documentElement.classList.toggle("sidebar-collapsed");
        localStorage.setItem(sidebarKey, String(collapsed));
		syncSidebarToggleState();
      });
    });

    document.querySelectorAll(".sidebar a").forEach((link) => {
      link.addEventListener("click", () => {
        document.documentElement.classList.remove("sidebar-mobile-open");
      });
    });

	const routedDialogPath = (value) => new URL(value, window.location.origin).pathname;
	const resetTokenDialog = (dialog) => {
	  if (dialog?.id !== "create-token-dialog" || dialog.dataset.tokenCreated !== "true") return;
	  dialog.querySelector("form")?.reset();
	  dialog.querySelector("[data-token-fields]")?.removeAttribute("hidden");
	  dialog.querySelector("[data-token-submit]")?.removeAttribute("hidden");
	  const close = dialog.querySelector("[data-token-close]");
	  if (close) close.textContent = "Cancel";
	  const result = dialog.querySelector("#api-token-result");
	  if (result) result.textContent = "The token secret will be shown once.";
	  delete dialog.dataset.tokenCreated;
	};
	const setupRoutedDialog = (dialog) => {
	  if (!dialog?.dataset.dialogUrl || dialog.dataset.dialogRouteReady === "true") return;
	  dialog.dataset.dialogRouteReady = "true";
	  dialog.addEventListener("close", () => {
		if (window.location.pathname !== routedDialogPath(dialog.dataset.dialogUrl)) return;
		const baseURL = dialog.dataset.dialogBaseUrl;
		if (!baseURL) return;
		if (window.history.state?.sableDialog === dialog.id) {
		  window.history.back();
		} else {
		  window.history.replaceState(null, "", baseURL);
		}
	  });
	};
	const showRoutedDialog = (dialog, pushURL = false) => {
	  if (!dialog) return;
	  resetTokenDialog(dialog);
	  setupRoutedDialog(dialog);
	  setupDialogTabs(dialog);
	  if (!dialog.open) {
		dialog.sableResetDialogTabs?.();
		dialog.showModal();
	  }
	  if (pushURL && dialog.dataset.dialogUrl) {
		const nextPath = routedDialogPath(dialog.dataset.dialogUrl);
		if (window.location.pathname !== nextPath) {
		  window.history.pushState({sableDialog: dialog.id}, "", dialog.dataset.dialogUrl);
		}
	  }
	  dialog.querySelector('input:not([type="hidden"]):not(.sr-only), textarea, select, button')?.focus();
	  dialog.querySelector("[data-token-owner]")?.dispatchEvent(new Event("change", {bubbles: true}));
	  if (dialog.id === "create-user-dialog") dialog.querySelector('input[name="roles"]')?.dispatchEvent(new Event("change", {bubbles: true}));
	};
	const syncRoutedDialogs = () => {
	  const dialogs = [...document.querySelectorAll("dialog[data-dialog-url]")];
	  dialogs.forEach(setupRoutedDialog);
	  const active = dialogs.find((dialog) => routedDialogPath(dialog.dataset.dialogUrl) === window.location.pathname);
	  dialogs.forEach((dialog) => {
		if (dialog !== active && dialog.open) dialog.close();
	  });
	  if (active) showRoutedDialog(active);
	};
	const openAutomaticDialogs = () => {
	  document.querySelectorAll('dialog[data-dialog-auto-open="true"]').forEach((dialog) => {
		if (!dialog.open) dialog.showModal();
		dialog.removeAttribute("data-dialog-auto-open");
	  });
	};
	window.addEventListener("popstate", syncRoutedDialogs);
	document.body.addEventListener("htmx:afterSwap", () => { syncRoutedDialogs(); openAutomaticDialogs(); });
	syncRoutedDialogs();
	openAutomaticDialogs();

	const legacyCopyText = (value) => {
	  const fallback = document.createElement("textarea");
	  fallback.value = value;
	  fallback.setAttribute("readonly", "");
	  fallback.style.position = "fixed";
	  fallback.style.inset = "0 auto auto -9999px";
	  document.body.append(fallback);
	  fallback.focus();
	  fallback.select();
	  const copied = document.execCommand("copy");
	  fallback.remove();
	  return copied;
	};
	const copyText = async (value) => {
	  if (navigator.clipboard?.writeText) {
		try {
		  await navigator.clipboard.writeText(value);
		  return;
		} catch (_) {
		  // Embedded browsers may expose the API while denying permission.
		}
	  }
	  if (!legacyCopyText(value)) throw new Error("Clipboard access is unavailable");
	};

	document.body.addEventListener("click", async (event) => {
	  const replicaDisabled = event.target.closest?.('[data-replica-primary-only="true"]');
	  if (replicaDisabled) {
		event.preventDefault();
		event.stopPropagation();
		return;
	  }
	  const dialogRow = event.target.closest("[data-dialog-open]");
	  if (dialogRow && dialogRow.tagName === "TR") {
		const dialog = document.getElementById(dialogRow.dataset.dialogOpen);
		showRoutedDialog(dialog);
		return;
	  }
	  const dialogOpen = event.target.closest("[data-dialog-open]");
	  if (dialogOpen) {
		const dialog = document.getElementById(dialogOpen.dataset.dialogOpen);
		dialogOpen.closest(".zone-action-menu")?.removeAttribute("open");
		showRoutedDialog(dialog, Boolean(dialogOpen.dataset.dialogUrl));
		dialog?.sableSelectDialogTab?.(dialogOpen.dataset.dialogTabTarget);
		return;
	  }
	  const dialogSwitch = event.target.closest("[data-dialog-switch]");
	  if (dialogSwitch) {
		const current = dialogSwitch.closest("dialog");
		const dialog = document.getElementById(dialogSwitch.dataset.dialogSwitch);
		current?.close();
		showRoutedDialog(dialog);
		dialog?.sableSelectDialogTab?.(dialogSwitch.dataset.dialogTabTarget);
		return;
	  }

	  const dialogClose = event.target.closest("[data-dialog-close]");
	  if (dialogClose) {
		dialogClose.closest("dialog")?.close();
		return;
	  }

	  const blockingTab = event.target.closest("[data-blocking-tab]");
	  if (blockingTab) {
		const root = blockingTab.closest("[data-blocking-root]");
		const selected = blockingTab.dataset.blockingTab;
		root?.querySelectorAll("[data-blocking-tab]").forEach((tab) => {
		  const active = tab.dataset.blockingTab === selected;
		  tab.classList.toggle("active", active);
		  tab.setAttribute("aria-selected", String(active));
		});
		root?.querySelectorAll("[data-blocking-panel]").forEach((panel) => {
		  panel.hidden = panel.dataset.blockingPanel !== selected;
		});
		document.querySelectorAll('.sidebar a[href^="/blocked?tab="]').forEach((link) => {
		  const allowedNavigation = link.getAttribute("href").includes("tab=allowed");
		  link.classList.toggle("active", allowedNavigation === (selected === "allowed"));
		});
		const nextURL = selected === "lists" ? "/blocked" : `/blocked?tab=${selected}`;
		window.history.replaceState(null, "", nextURL);
		return;
	  }

	  const recordType = event.target.closest("[data-record-type-choice]");
	  if (recordType) {
		selectRecordType(recordType.closest("form"), recordType.dataset.recordTypeChoice);
		return;
	  }

	  const catalogTab = event.target.closest("[data-catalog-tab]");
	  if (catalogTab) {
		const dialog = catalogTab.closest("dialog");
		const selected = catalogTab.dataset.catalogTab;
		dialog?.querySelectorAll("[data-catalog-tab]").forEach((tab) => tab.classList.toggle("active", tab.dataset.catalogTab === selected));
		dialog?.querySelectorAll("[data-catalog-panel]").forEach((panel) => { panel.hidden = panel.dataset.catalogPanel !== selected; });
		return;
	  }

      const quickQuery = event.target.closest("[data-query-type]");
      if (quickQuery) {
        const select = document.querySelector("#record-type");
        if (select) select.value = quickQuery.dataset.queryType;
      }

      const copyButton = event.target.closest("[data-copy-target]");
      if (!copyButton) return;
      const target = document.getElementById(copyButton.dataset.copyTarget);
      if (!target) return;
	  const label = copyButton.querySelector("[data-copy-label]");
	  const previousLabel = label?.textContent;
	  const previousAriaLabel = copyButton.getAttribute("aria-label");
      try {
		const value = target.textContent || "";
		await copyText(value);
		copyButton.classList.add("is-copied");
		copyButton.setAttribute("aria-label", "Copied to clipboard");
		copyButton.setAttribute("title", "Copied");
		if (label) label.textContent = "Copied";
		setTimeout(() => {
		  copyButton.classList.remove("is-copied");
		  if (previousAriaLabel === null) copyButton.removeAttribute("aria-label");
		  else copyButton.setAttribute("aria-label", previousAriaLabel);
		  copyButton.setAttribute("title", previousAriaLabel || "Copy to clipboard");
		  if (label) label.textContent = previousLabel;
		}, 2000);
      } catch (_) {
		copyButton.setAttribute("aria-label", "Copy failed");
		copyButton.setAttribute("title", "Copy failed — select the value and press Command-C");
		if (label) label.textContent = "Copy failed";
      }
    });

	// Keep the live chart refresh from replacing an open custom-range picker.
	document.body.addEventListener("htmx:beforeRequest", (event) => {
	  const source = event.detail?.elt;
	  if (source?.id === "query-statistics" && source.querySelector("[data-chart-range-popover]:not([hidden])")) {
		event.preventDefault();
	  }
	  if (source?.id === "cluster-live-status" && document.querySelector("dialog.confirmation-dialog[open]")) {
		event.preventDefault();
	  }
	});
	document.body.addEventListener("submit", (event) => {
	  if (!event.target.closest?.('[data-replica-read-only-form="true"]')) return;
	  event.preventDefault();
	  event.stopImmediatePropagation();
	}, true);

	document.body.addEventListener("htmx:confirm", (event) => {
	  const question = event.detail?.question;
	  if (!question) return;
	  event.preventDefault();
	  const source = event.detail?.elt;
	  const confirmation = source?.closest?.("[data-confirm-title]") || source;
	  confirmAction(question, {
		title: confirmation?.dataset.confirmTitle,
		action: confirmation?.dataset.confirmAction,
		tone: confirmation?.dataset.confirmTone,
	  }).then((accepted) => {
		if (accepted) event.detail.issueRequest(true);
	  });
	});

	const updateTopStatsDialog = (dialog) => {
	  if (!dialog) return;
	  const query = dialog.querySelector("[data-top-stats-search]")?.value.trim().toLowerCase() || "";
	  const limit = Number(dialog.querySelector("[data-top-stats-limit]")?.value || 100);
	  const rows = [...dialog.querySelectorAll("[data-top-stats-row]")];
	  let visible = 0;
	  let hits = 0;
	  rows.forEach((row) => {
		const matches = Number(row.dataset.rank) <= limit && row.dataset.search.includes(query);
		row.hidden = !matches;
		if (matches) {
		  visible++;
		  hits += Number(row.dataset.hits) || 0;
		}
	  });
	  const empty = dialog.querySelector("[data-top-stats-empty]");
	  if (empty) empty.hidden = visible !== 0 || rows.length === 0;
	  const count = dialog.querySelector("[data-top-stats-count]");
	  if (count) {
		const noun = dialog.id.includes("clients") ? "clients" : "domains";
		count.textContent = `${visible.toLocaleString()}${query ? ` of ${Math.min(rows.length, limit).toLocaleString()}` : ""} ${noun}`;
	  }
	  const total = dialog.querySelector("[data-top-stats-total]");
	  if (total) total.textContent = `${hits.toLocaleString()} hits`;
	};

	document.body.addEventListener("input", (event) => {
	  if (event.target.matches("[data-top-stats-search]")) {
		updateTopStatsDialog(event.target.closest("[data-top-stats-dialog]"));
		return;
	  }
	  if (event.target.matches("[data-zone-import-text]")) {
		const form = event.target.closest("form");
		const file = form?.querySelector("[data-zone-file]");
		const submit = form?.querySelector("[data-zone-import-submit]");
		if (submit) submit.disabled = !event.target.value.trim() && !file?.files?.length;
		return;
	  }

	  if (event.target.matches("[data-zone-search]")) {
		const root = event.target.closest("[data-zone-root]");
		const query = event.target.value.trim().toLowerCase();
		const type = root.querySelector("[data-zone-type-filter]")?.value || "all";
		const status = root.querySelector("[data-zone-status-filter]")?.value || "all";
		const rows = [...root.querySelectorAll("[data-zone-row]")];
		let visible = 0;
		rows.forEach((row) => {
		  const matches = row.dataset.zoneName.includes(query) && (type === "all" || row.dataset.zoneType === type) && (status === "all" || row.dataset.zoneStatus === status);
		  row.hidden = !matches;
		  if (matches) visible++;
		});
		const empty = root.querySelector("[data-zone-filter-empty]");
		if (empty) empty.hidden = visible !== 0 || rows.length === 0;
		return;
	  }

	  if (event.target.matches("[data-record-search]")) {
		const root = event.target.closest("[data-zone-root]");
		const query = event.target.value.trim().toLowerCase();
		const type = root.querySelector("[data-record-type-filter]")?.value || "all";
		const rows = [...root.querySelectorAll("[data-record-row]")];
		let visible = 0;
		rows.forEach((row) => {
		  const matches = row.dataset.recordName.includes(query) && (type === "all" || row.dataset.recordType === type);
		  row.hidden = !matches;
		  if (matches) visible++;
		});
		const empty = root.querySelector("[data-record-filter-empty]");
		if (empty) empty.hidden = visible !== 0 || rows.length === 0;
		return;
	  }

	  if (event.target.matches("[data-domain-search]")) {
		const root = event.target.closest("[data-blocking-root]");
		const kind = event.target.dataset.domainSearch;
		const query = event.target.value.trim().toLowerCase();
		const rows = [...root.querySelectorAll(`[data-policy-domain][data-domain-kind="${kind}"]`)];
		let visible = 0;
		rows.forEach((row) => {
		  const matches = row.dataset.policyDomain.toLowerCase().includes(query);
		  row.hidden = !matches;
		  if (matches) visible++;
		});
		const empty = root.querySelector(`[data-domain-empty="${kind}"]`);
		if (empty) empty.hidden = visible !== 0 || rows.length === 0;
		const shown = root.querySelector(`[data-domain-shown="${kind}"]`);
		if (shown) {
		  shown.hidden = !query || visible === rows.length;
		  shown.textContent = `(${visible} shown)`;
		}
		return;
	  }

	  if (event.target.matches("[data-blocking-search]")) {
		const root = event.target.closest("[data-blocking-root]");
		const query = event.target.value.trim().toLowerCase();
		const rows = [...root.querySelectorAll("[data-blocked-domain]")];
		let visible = 0;
		rows.forEach((row) => {
		  const matches = row.dataset.blockedDomain.toLowerCase().includes(query);
		  row.hidden = !matches;
		  if (matches) visible++;
		});
		const empty = root.querySelector("[data-blocking-filter-empty]");
		if (empty) empty.hidden = visible !== 0 || rows.length === 0;
		return;
	  }

	  if (!event.target.matches("[data-cache-search]")) return;
	  const dialog = event.target.closest("dialog");
	  const query = event.target.value.trim().toLowerCase();
	  const rows = [...dialog.querySelectorAll("[data-cache-domain]")];
	  let visible = 0;
	  rows.forEach((row) => {
		const matches = row.dataset.cacheDomain.toLowerCase().includes(query);
		row.hidden = !matches;
		if (matches) visible++;
	  });
	  const empty = dialog.querySelector("[data-cache-empty]");
	  if (empty) empty.hidden = visible !== 0 || rows.length === 0;
	});

	document.body.addEventListener("change", (event) => {
	  if (event.target.matches("[data-time-format-preference]")) {
		const value = event.target.value === "24" ? "24" : "12";
		document.cookie = `sable_time_format=${value}; Path=/; Max-Age=31536000; SameSite=Lax`;
		window.location.reload();
		return;
	  }
	  if (event.target.matches("[data-top-stats-limit]")) {
		updateTopStatsDialog(event.target.closest("[data-top-stats-dialog]"));
		return;
	  }
	  if (event.target.matches("[data-dnssec-denial]")) {
		syncDNSSECDenial(event.target);
		return;
	  }
	  if (event.target.matches("[data-zone-create-type]")) {
		const form = event.target.closest("[data-zone-create-form]");
		const type = event.target.value;
		const sectionsByType = {
		  primary: [],
		  secondary: ["transfer"],
		  stub: ["transfer", "resolution"],
		  forwarder: ["forwarder", "resolution"],
		  alias: ["alias"],
		};
		const active = sectionsByType[type] || [];
		form?.querySelectorAll("[data-zone-create-options]").forEach((section) => {
		  const shown = active.includes(section.dataset.zoneCreateOptions);
		  section.hidden = !shown;
		  section.querySelectorAll("input, textarea, select").forEach((field) => { field.disabled = !shown; });
		});
		const primaryProtocol = form?.querySelector("[data-zone-primary-protocol]");
		const stubProtocol = primaryProtocol?.querySelector("[data-stub-protocol]");
		if (stubProtocol) stubProtocol.disabled = type !== "stub";
		if (primaryProtocol && type === "stub" && primaryProtocol.value === "tcp") primaryProtocol.value = "udp";
		if (primaryProtocol && type === "secondary" && primaryProtocol.value === "udp") primaryProtocol.value = "tcp";
		return;
	  }
	  if (event.target.matches("[data-record-more-types]")) {
		selectRecordType(event.target.closest("form"), event.target.value);
		return;
	  }
	  if (event.target.matches("[data-zone-file]")) {
		const file = event.target.files?.[0];
		const form = event.target.closest("form");
		const textarea = form?.querySelector("[data-zone-import-text]");
		const filename = form?.querySelector("[data-zone-file-name]");
		const submit = form?.querySelector("[data-zone-import-submit]");
		if (filename) filename.textContent = file?.name || "No file selected";
		if (submit) submit.disabled = !file && !textarea?.value.trim();
		if (file && textarea) {
		  file.text().then((contents) => {
			textarea.value = contents;
			textarea.dispatchEvent(new Event("input", {bubbles: true}));
		  }).catch(() => {
			if (filename) filename.textContent = `${file.name} (preview unavailable)`;
		  });
		}
		return;
	  }
	  if (event.target.matches("[data-zone-type-filter], [data-zone-status-filter]")) {
		event.target.closest("[data-zone-root]")?.querySelector("[data-zone-search]")?.dispatchEvent(new Event("input", {bubbles: true}));
		return;
	  }
	  if (event.target.matches("[data-record-type-filter]")) {
		event.target.closest("[data-zone-root]")?.querySelector("[data-record-search]")?.dispatchEvent(new Event("input", {bubbles: true}));
		return;
	  }
	  if (event.target.matches("[data-domain-import]") && event.target.files?.length) {
		event.target.form?.requestSubmit();
	  }
	});

	const openMenus = ".pause-menu[open], .zone-action-menu[open], .about-update-menu[open]";
	document.addEventListener("pointerdown", (event) => {
	  document.querySelectorAll(openMenus).forEach((menu) => {
		if (!menu.contains(event.target)) menu.removeAttribute("open");
	  });
	});
	document.addEventListener("keydown", (event) => {
	  if (event.key !== "Escape") return;
	  document.querySelectorAll(openMenus).forEach((menu) => {
		menu.removeAttribute("open");
		menu.querySelector("summary")?.focus();
	  });
	});

	document.body.addEventListener("change", (event) => {
	  if (!event.target.matches('input[name="response_type"], input[name="blocking_response_type"]')) return;
	  const form = event.target.closest("form");
	  const custom = form?.querySelector("[data-custom-addresses]");
	  if (custom) custom.hidden = event.target.value !== "custom";
	});
  });
})();
