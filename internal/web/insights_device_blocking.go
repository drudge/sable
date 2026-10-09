package web

import (
	"cmp"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

// holdExtension is how much Add 30 Minutes adds to a hold.
const holdExtension = 30 * time.Minute

// deviceBlockingView says how blocking treats a device: its rule set and what
// put it there, and any hold. It matches the device the way the DNS server
// does, by its busiest address and its hardware address.
func deviceBlockingView(configuration config.Config, device pages.InsightDeviceView, display pages.TimeDisplay, now time.Time) pages.InsightDeviceBlockingView {
	view := pages.InsightDeviceBlockingView{}
	for _, set := range configuration.Blocking.RuleSets {
		view.RuleSets = append(view.RuleSets, set.Name)
	}
	address := ""
	if len(device.Addresses) > 0 {
		address = device.Addresses[0].Address
	}
	own := deviceOwnEntries(device)
	entries, sets := ruleSetEntries(configuration)
	if entry, found := dnsserver.MatchClient(entries, address, device.MAC); found {
		view.RuleSet, view.Off = sets[entry].name, sets[entry].off
		view.MatchedBy = clientEntryPhrase(entry)
		if own[normalizedEntry(entry)] {
			view.Own = view.RuleSet
		}
	}
	// What the device falls back to without an entry of its own: a network's
	// rule set, or the default.
	view.Inherited = "Default"
	others := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !own[normalizedEntry(entry)] {
			others = append(others, entry)
		}
	}
	if entry, found := dnsserver.MatchClient(others, address, device.MAC); found {
		view.Inherited = sets[entry].name + " (from " + clientEntryPhrase(entry) + ")"
	}

	holds := make([]string, 0, len(configuration.Blocking.Holds))
	active := make(map[string]config.Hold, len(configuration.Blocking.Holds))
	for _, hold := range configuration.Blocking.Holds {
		if hold.Active(now) {
			entry := cmp.Or(hold.MAC, hold.Address)
			holds = append(holds, entry)
			active[entry] = hold
		}
	}
	if entry, found := dnsserver.MatchClient(holds, address, device.MAC); found {
		hold := active[entry]
		view.Held, view.HoldEntry = true, entry
		if !own[normalizedEntry(entry)] {
			view.HoldFrom = clientEntryPhrase(entry)
		}
		if !hold.Until.IsZero() {
			view.HoldUntil = holdTimeLabel(display.In(hold.Until), display.In(now))
			view.HoldEndsAt = hold.Until.UnixMilli()
			view.HoldLeft = timeLeft(hold.Until.Sub(now))
		}
	}
	view.DefaultUntil = display.In(now.Add(2 * time.Hour)).Truncate(30 * time.Minute).Format("15:04")
	return view
}

type ruleSetEntry struct {
	name string
	off  bool
}

// ruleSetEntries lists every client that names a rule set, in the order the
// DNS server reads them.
func ruleSetEntries(configuration config.Config) ([]string, map[string]ruleSetEntry) {
	var entries []string
	sets := make(map[string]ruleSetEntry)
	add := func(entry string, set ruleSetEntry) {
		if _, taken := sets[entry]; !taken {
			sets[entry] = set
		}
		entries = append(entries, entry)
	}
	for _, set := range configuration.Blocking.RuleSets {
		for _, client := range configuration.Clients {
			if client.RuleSet == set.Name {
				add(cmp.Or(client.MAC, client.Address), ruleSetEntry{name: set.Name, off: set.Off})
			}
		}
	}
	return entries, sets
}

// deviceOwnEntries are the client entries that name only this device: its
// hardware address and each of its exact addresses.
func deviceOwnEntries(device pages.InsightDeviceView) map[string]bool {
	own := map[string]bool{}
	if device.MAC != "" {
		own[normalizedEntry(device.MAC)] = true
	}
	for _, address := range device.Addresses {
		own[normalizedEntry(address.Address)] = true
	}
	return own
}

func normalizedEntry(entry string) string {
	client := clientForEntry(entry)
	return cmp.Or(client.MAC, client.Address)
}

// clientForEntry turns a client entry back into the device it names.
func clientForEntry(entry string) config.Client {
	if mac, err := net.ParseMAC(entry); err == nil {
		return config.Client{MAC: mac.String()}
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if prefix.IsSingleIP() {
			return config.Client{Address: prefix.Addr().String()}
		}
		return config.Client{Address: prefix.Masked().String()}
	}
	if address, err := netip.ParseAddr(entry); err == nil {
		return config.Client{Address: address.Unmap().WithZone("").String()}
	}
	return config.Client{Address: entry}
}

// clientEntryPhrase says what a client entry names, to finish "from …".
func clientEntryPhrase(entry string) string {
	client := clientForEntry(entry)
	switch {
	case client.MAC != "":
		return "its hardware address"
	case strings.Contains(client.Address, "/"):
		return "the network " + client.Address
	default:
		return "the address " + client.Address
	}
}

// holdTimeLabel says when a hold ends: a time today, or a day and time.
func holdTimeLabel(until, now time.Time) string {
	if until.Year() == now.Year() && until.YearDay() == now.YearDay() {
		return until.Format("3:04 PM")
	}
	return until.Format("Mon 3:04 PM")
}

// holdUntil reads how long the hold form asked for: 30 minutes, an hour, a
// time of day (the next one, in the viewer's time zone), or no end.
func holdUntil(choice, clock string, display pages.TimeDisplay, now time.Time) (time.Time, error) {
	switch choice {
	case "30m":
		return now.Add(30 * time.Minute), nil
	case "1h":
		return now.Add(time.Hour), nil
	case "off":
		return time.Time{}, nil
	case "until":
		parsed, err := time.Parse("15:04", strings.TrimSpace(clock))
		if err != nil {
			return time.Time{}, refuse(http.StatusUnprocessableEntity, "Pick a time to block everything until.")
		}
		local := display.In(now)
		until := time.Date(local.Year(), local.Month(), local.Day(), parsed.Hour(), parsed.Minute(), 0, 0, local.Location())
		if !until.After(local) {
			until = until.AddDate(0, 0, 1)
		}
		return until, nil
	default:
		return time.Time{}, refuse(http.StatusUnprocessableEntity, "Pick how long to block everything.")
	}
}

// deviceRuleSet puts the drawer's device in a rule set, or takes it out of
// its own.
func (server *Server) deviceRuleSet(writer http.ResponseWriter, request *http.Request) {
	server.changeDeviceBlocking(writer, request, "rule-set", func(device config.Client, label string) (string, error) {
		addresses, err := server.deviceAddresses(request.Context(), request.FormValue("key"))
		if err != nil {
			return "", err
		}
		device.RuleSet = strings.TrimSpace(request.FormValue("rule_set"))
		return server.ruleSetService().Assign(request.Context(), requestActor(request, ""), device, addresses, label)
	})
}

// deviceHold blocks everything for the drawer's device, adds to its hold, or
// ends it. A hold the device has through a network is that network's.
func (server *Server) deviceHold(writer http.ResponseWriter, request *http.Request) {
	server.changeDeviceBlocking(writer, request, "hold", func(device config.Client, label string) (string, error) {
		who, now := requestActor(request, ""), time.Now()
		if entry := strings.TrimSpace(request.FormValue("entry")); entry != "" {
			device = clientForEntry(entry)
		}
		switch request.FormValue("action") {
		case "end":
			if _, err := server.holdService().End(request.Context(), who, device); err != nil {
				return "", err
			}
			return "Blocking for " + label + " is back to normal.", nil
		case "extend":
			hold, held := config.HoldFor(server.config.Current().Config.Blocking.Holds, device, now)
			if !held || hold.Until.IsZero() {
				return "", refuse(http.StatusConflict, "This hold has no end to add to.")
			}
			until := hold.Until.Add(holdExtension)
			if until.After(now.Add(maximumHoldMinutes * time.Minute)) {
				return "", refuse(http.StatusUnprocessableEntity, "A hold can last up to a week. Choose Until Turned Off for longer.")
			}
			if _, err := server.holdService().Hold(request.Context(), who, device, until); err != nil {
				return "", err
			}
			return "Added 30 minutes.", nil
		default:
			display := requestTimeDisplay(request)
			until, err := holdUntil(request.FormValue("hold"), request.FormValue("until"), display, now)
			if err != nil {
				return "", err
			}
			if _, err := server.holdService().Hold(request.Context(), who, device, until); err != nil {
				return "", err
			}
			if until.IsZero() {
				return "Everything is blocked for " + label + " until you turn it off.", nil
			}
			return "Everything is blocked for " + label + " until " + holdTimeLabel(display.In(until), display.In(now)) + ".", nil
		}
	})
}

// changeDeviceBlocking runs one blocking change from the device drawer and
// shows the drawer again: with a message, or with the editor still open and
// the problem when the change fails.
func (server *Server) changeDeviceBlocking(writer http.ResponseWriter, request *http.Request, editor string, change func(config.Client, string) (string, error)) {
	console := server.consoleView(request)
	if !console.CanLogs || !console.CanWriteBlocking {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	window := insightsWindow(request.FormValue("range"), time.Now())
	key := request.FormValue("key")
	device, err := clientForDeviceKey(key, "")
	message := ""
	if err == nil {
		message, err = change(device, deviceLabel(server.config.Current().Config.Clients, device, key))
	}
	if err != nil {
		server.logger.Warn("change device blocking", "client", requestClientIP(request), "error", err)
		writeFragmentStatus(writer, serviceStatus(err))
		server.renderDeviceDrawer(writer, request, console, window, key, editor, "", sentence(err.Error()))
		return
	}
	writer.Header().Set("HX-Trigger", "insightsChanged")
	server.renderDeviceDrawer(writer, request, console, window, key, "", message, "")
}

// deviceLabel names a device in messages and the Change Center: by the name
// the operator gave it, or by its hardware address or address.
func deviceLabel(clients []config.Client, device config.Client, key string) string {
	for _, client := range clients {
		if client.Name != "" && normalizedEntry(cmp.Or(client.MAC, client.Address)) == cmp.Or(device.MAC, device.Address) {
			return client.Name
		}
	}
	return deviceKeyIdentifier(key)
}

// timeLeft says how long a hold has to run, the way the countdown in app.js
// does: "under a minute left", "25 minutes left", "1 hour 5 minutes left".
func timeLeft(remaining time.Duration) string {
	minutes := int(remaining.Round(time.Minute) / time.Minute)
	if minutes < 1 {
		return "under a minute left"
	}
	days, hours := minutes/(24*60), minutes/60%24
	minutes %= 60
	var parts []string
	for _, part := range []struct {
		count       int
		one, plural string
	}{{days, "day", "days"}, {hours, "hour", "hours"}, {minutes, "minute", "minutes"}} {
		if part.count > 0 && len(parts) < 2 {
			parts = append(parts, fmt.Sprintf("%d %s", part.count, ifPlural(part.count, part.one, part.plural)))
		}
	}
	return strings.Join(parts, " ") + " left"
}

func ifPlural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}
