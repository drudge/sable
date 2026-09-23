package devices

import (
	"cmp"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/services"
)

// Confidence is how sure a type guess is.
type Confidence string

const (
	// ConfidenceSet marks a type the operator chose.
	ConfidenceSet Confidence = "set"
	// ConfidenceHigh needs strong clues of more than one kind that agree.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium rests on one strong clue or several weak ones.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow is a lean, shown as a possibility rather than a fact.
	ConfidenceLow Confidence = "low"
)

// Guess is what kind of device Sable thinks a device is, and why.
type Guess struct {
	// Type is one of config.ClientTypes, or empty when Sable has no guess.
	Type       string
	Confidence Confidence
	Reasons    []insights.Reason
}

// typeLabels names each device type for people.
var typeLabels = map[string]string{
	"phone": "Phone", "tablet": "Tablet", "computer": "Computer", "server": "Server", "tv": "TV",
	"streaming-player": "Streaming player", "smart-speaker": "Smart speaker", "speaker": "Speaker",
	"camera": "Camera", "doorbell": "Doorbell", "game-console": "Game console", "printer": "Printer",
	"storage": "Network storage", "network": "Network equipment", "thermostat": "Thermostat",
	"lighting": "Smart lighting", "smart-plug": "Smart plug", "smart-home": "Smart home device", "watch": "Watch",
}

// TypeLabel names a device type for people.
func TypeLabel(kind string) string { return typeLabels[kind] }

// TypeLabels lists every type with its label, in the order a picker offers them.
func TypeLabels() [][2]string {
	labels := make([][2]string, 0, len(typeLabels))
	for kind, label := range typeLabels {
		labels = append(labels, [2]string{kind, label})
	}
	slices.SortFunc(labels, func(left, right [2]string) int { return cmp.Compare(left[1], right[1]) })
	return labels
}

// clue is one piece of evidence for a type, with how much it counts.
type clue struct {
	kind   string
	weight int
}

// makerClues are what each hardware maker mostly builds. A maker that builds
// many kinds of things gets small weights, so its clue only tips a guess
// that other evidence already supports.
var makerClues = map[string][]clue{
	"Ring": {{"doorbell", 3}, {"camera", 2}}, "Arlo": {{"camera", 4}}, "Wyze": {{"camera", 3}}, "Amcrest": {{"camera", 4}},
	"Sonos": {{"speaker", 4}}, "Roku": {{"streaming-player", 4}}, "Google Nest": {{"smart-home", 3}},
	"ecobee": {{"thermostat", 4}}, "Philips Hue": {{"lighting", 4}}, "Sony PlayStation": {{"game-console", 4}},
	"Nintendo": {{"game-console", 4}}, "Raspberry Pi": {{"server", 2}, {"computer", 1}},
	"Espressif": {{"smart-plug", 2}, {"smart-home", 2}}, "Tuya": {{"smart-plug", 2}, {"smart-home", 2}},
	"Brother": {{"printer", 3}}, "Epson": {{"printer", 3}}, "Canon": {{"printer", 2}}, "HP": {{"printer", 1}, {"computer", 1}},
	"Synology": {{"storage", 4}}, "QNAP": {{"storage", 4}}, "Ubiquiti": {{"network", 3}}, "Cisco": {{"network", 2}},
	"Netgear": {{"network", 2}}, "eero": {{"network", 3}}, "TP-Link": {{"network", 1}, {"smart-plug", 1}},
	"Apple": {{"phone", 1}, {"computer", 1}}, "Samsung": {{"phone", 1}, {"tv", 1}}, "LG": {{"tv", 2}},
	"Vizio": {{"tv", 4}}, "Amazon": {{"smart-speaker", 1}, {"streaming-player", 1}}, "Intel": {{"computer", 2}},
	"Dell": {{"computer", 3}}, "Lenovo": {{"computer", 2}}, "ASUS": {{"computer", 1}, {"network", 1}},
	"Microsoft": {{"computer", 2}}, "Realtek": {{"computer", 1}}, "AzureWave": {{"computer", 1}},
	"Foxconn": {{"computer", 1}}, "Lite-On": {{"computer", 1}}, "Garmin": {{"watch", 3}},
	"iRobot": {{"smart-home", 4}}, "Chamberlain": {{"smart-home", 4}}, "Belkin": {{"smart-plug", 2}},
}

// nameClues are words in a device's name that say what it is. They are
// matched against the words of the name, so "dock-camera-02" matches
// "camera" and "scanner" does not match "can".
var nameClues = map[string][]clue{
	"iphone": {{"phone", 5}}, "android": {{"phone", 3}}, "galaxy": {{"phone", 3}}, "pixel": {{"phone", 3}},
	"phone": {{"phone", 4}}, "ipad": {{"tablet", 5}}, "tablet": {{"tablet", 4}}, "kindle": {{"tablet", 3}},
	"macbook": {{"computer", 5}}, "laptop": {{"computer", 5}}, "thinkpad": {{"computer", 5}}, "notebook": {{"computer", 4}},
	"imac": {{"computer", 5}}, "desktop": {{"computer", 5}}, "workstation": {{"computer", 5}}, "pc": {{"computer", 3}},
	"surface": {{"computer", 3}}, "mbp": {{"computer", 4}}, "server": {{"server", 5}}, "nas": {{"storage", 5}},
	"diskstation": {{"storage", 5}}, "backup": {{"storage", 2}, {"server", 1}}, "printer": {{"printer", 5}},
	"laserjet": {{"printer", 5}}, "officejet": {{"printer", 5}}, "deskjet": {{"printer", 5}}, "press": {{"printer", 2}},
	"camera": {{"camera", 5}}, "cam": {{"camera", 4}}, "ipcam": {{"camera", 5}}, "doorbell": {{"doorbell", 6}},
	"thermostat": {{"thermostat", 6}}, "tv": {{"tv", 5}}, "television": {{"tv", 5}}, "bravia": {{"tv", 5}},
	"display": {{"tv", 3}}, "signage": {{"tv", 3}}, "roku": {{"streaming-player", 5}}, "firetv": {{"streaming-player", 5}},
	"appletv": {{"streaming-player", 5}}, "chromecast": {{"streaming-player", 5}}, "shield": {{"streaming-player", 3}},
	"echo": {{"smart-speaker", 4}}, "alexa": {{"smart-speaker", 4}}, "homepod": {{"smart-speaker", 5}},
	"sonos": {{"speaker", 5}}, "speaker": {{"speaker", 4}}, "xbox": {{"game-console", 5}}, "playstation": {{"game-console", 5}},
	"ps4": {{"game-console", 5}}, "ps5": {{"game-console", 5}}, "nintendo": {{"game-console", 5}}, "watch": {{"watch", 4}},
	"plug": {{"smart-plug", 4}}, "outlet": {{"smart-plug", 4}}, "bulb": {{"lighting", 4}}, "lamp": {{"lighting", 3}},
	"hue": {{"lighting", 3}}, "router": {{"network", 5}}, "gateway": {{"network", 4}}, "ap": {{"network", 2}},
	"switch": {{"network", 2}}, "scanner": {{"smart-home", 1}},
}

// serviceClues are the apps whose use says what a device is. Apps anyone
// might open on a phone or laptop are left out; these are the services a
// device talks to because of what it is.
var serviceClues = map[string][]clue{
	"ring": {{"doorbell", 2}, {"camera", 2}}, "wyze": {{"camera", 3}}, "arlo": {{"camera", 3}}, "blink": {{"camera", 3}},
	"eufy": {{"camera", 3}}, "simplisafe": {{"camera", 2}}, "philips-hue": {{"lighting", 3}}, "sonos": {{"speaker", 3}},
	"roku": {{"streaming-player", 3}}, "fire-tv": {{"streaming-player", 3}}, "chromecast": {{"streaming-player", 3}},
	"lg-webos": {{"tv", 4}}, "vizio": {{"tv", 4}}, "xbox": {{"game-console", 2}}, "playstation": {{"game-console", 2}},
	"nintendo": {{"game-console", 2}}, "hp-printing": {{"printer", 3}}, "epson": {{"printer", 3}}, "brother": {{"printer", 3}},
	"synology": {{"storage", 3}}, "qnap": {{"storage", 3}}, "windows-update": {{"computer", 3}}, "android": {{"phone", 2}},
	"alexa": {{"smart-speaker", 2}}, "ecobee": {{"thermostat", 3}}, "tuya": {{"smart-home", 2}},
	"tp-link-kasa": {{"smart-plug", 2}}, "smartthings": {{"smart-home", 2}}, "myq": {{"smart-home", 3}},
	"roomba": {{"smart-home", 3}}, "raspberry-pi": {{"server", 1}, {"computer", 1}},
	"homebrew": {{"computer", 3}}, "vscode": {{"computer", 3}}, "steam": {{"computer", 2}},
}

// ServiceClueIDs lists the services whose use is evidence of a device type,
// so a caller reads only the names that could matter.
func ServiceClueIDs() []string {
	ids := make([]string, 0, len(serviceClues))
	for id := range serviceClues {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Classify guesses what kind of device a device is from its maker, its name,
// and the services it uses. A type the operator set always wins. The guess
// keeps only the reasons that support it, so the console can show exactly
// why Sable thinks so.
func Classify(device Device, used []services.Service) Guess {
	if device.Type != "" {
		return Guess{Type: device.Type, Confidence: ConfidenceSet, Reasons: []insights.Reason{{Text: "You set this type"}}}
	}
	type evidence struct {
		score   int
		sources map[string]bool
		reasons []insights.Reason
	}
	byType := make(map[string]*evidence)
	add := func(source string, clues []clue, reason insights.Reason) {
		for _, clue := range clues {
			entry := byType[clue.kind]
			if entry == nil {
				entry = &evidence{sources: map[string]bool{}}
				byType[clue.kind] = entry
			}
			entry.score += clue.weight
			entry.sources[source] = true
			if !slices.Contains(entry.reasons, reason) {
				entry.reasons = append(entry.reasons, reason)
			}
		}
	}
	if device.Vendor != "" {
		add("maker", makerClues[device.Vendor], insights.Reason{Text: "Made by " + device.Vendor})
	}
	// A name the operator gave is theirs, but it still describes the device.
	if device.Name != "" {
		seen := map[string]bool{}
		for _, word := range nameWords(device.Name) {
			if clues, found := nameClues[word]; found && !seen[word] {
				seen[word] = true
				add("name", clues, insights.Reason{Text: "Named", Code: device.Name})
			}
		}
	}
	for _, service := range used {
		if clues, found := serviceClues[service.ID]; found {
			add("services", clues, insights.Reason{Text: "Talks to " + service.Name})
		}
	}

	ranked := make([]string, 0, len(byType))
	for kind := range byType {
		ranked = append(ranked, kind)
	}
	slices.SortFunc(ranked, func(left, right string) int {
		if order := cmp.Compare(byType[right].score, byType[left].score); order != 0 {
			return order
		}
		return cmp.Compare(left, right)
	})
	if len(ranked) == 0 {
		return Guess{}
	}
	best := byType[ranked[0]]
	runnerUp := 0
	if len(ranked) > 1 {
		runnerUp = byType[ranked[1]].score
	}
	confidence := ConfidenceLow
	switch {
	case best.score >= 5 && len(best.sources) >= 2:
		confidence = ConfidenceHigh
	case best.score >= 4:
		confidence = ConfidenceMedium
	case best.score < 2:
		return Guess{}
	}
	// A close second means the evidence does not really choose.
	if best.score-runnerUp <= 1 {
		switch confidence {
		case ConfidenceHigh:
			confidence = ConfidenceMedium
		case ConfidenceMedium:
			confidence = ConfidenceLow
		default:
			return Guess{}
		}
	}
	return Guess{Type: ranked[0], Confidence: confidence, Reasons: best.reasons}
}

// nameWords splits a device name into lower-case words at every character
// that is not a letter or digit, and also at digits, so "ps5" stays whole but
// "camera02" gives "camera".
func nameWords(name string) []string {
	fields := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	words := make([]string, 0, len(fields)*2)
	for _, field := range fields {
		words = append(words, field)
		if trimmed := strings.TrimRight(field, "0123456789"); trimmed != field && trimmed != "" {
			words = append(words, trimmed)
		}
	}
	return words
}

// Identify guesses every device's type. names holds, per client address, the
// names it queried that belong to services in ServiceClueIDs.
func Identify(list []Device, names map[string][]string) {
	for index := range list {
		seen := make(map[string]bool)
		used := make([]services.Service, 0)
		for _, address := range list[index].Addresses {
			for _, name := range names[address.Address] {
				if service, found := services.Lookup(name); found && !seen[service.ID] {
					seen[service.ID] = true
					used = append(used, service)
				}
			}
		}
		slices.SortFunc(used, func(left, right services.Service) int { return cmp.Compare(left.ID, right.ID) })
		list[index].Guess = Classify(list[index], used)
	}
}

// GuessText states a guess with as much certainty as it has: "Doorbell",
// "Probably a doorbell", or "Maybe a doorbell".
func GuessText(guess Guess) string {
	label := TypeLabel(guess.Type)
	switch guess.Confidence {
	case ConfidenceSet, ConfidenceHigh:
		return label
	case ConfidenceMedium:
		return "Probably " + article(label) + " " + strings.ToLower(label)
	default:
		return "Maybe " + article(label) + " " + strings.ToLower(label)
	}
}

// describeDevice opens a sentence about a device with what it is and who made
// it, when Sable knows: "Probably a doorbell made by Ring. "
func describeDevice(device Device) string {
	switch {
	case device.Guess.Type != "" && device.Guess.Confidence != ConfidenceLow:
		text := GuessText(device.Guess)
		if device.Guess.Confidence == ConfidenceSet || device.Guess.Confidence == ConfidenceHigh {
			text = article(text) + " " + strings.ToLower(text)
			text = strings.ToUpper(text[:1]) + text[1:]
		}
		if device.Vendor != "" {
			text += " made by " + device.Vendor
		}
		return text + ". "
	case device.Vendor != "":
		return "Made by " + device.Vendor + ". "
	default:
		return ""
	}
}

func article(word string) string {
	if word != "" && strings.ContainsRune("AEIOUaeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}
