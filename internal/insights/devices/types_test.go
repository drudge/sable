package devices

import (
	"testing"

	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
)

func service(t *testing.T, id string) services.Service {
	t.Helper()
	if id == mqttService.ID {
		return mqttService
	}
	found, ok := services.Find(id)
	if !ok {
		t.Fatalf("no service %q", id)
	}
	return found
}

func TestClassifyWeighsMakerNameAndServices(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		device     Device
		used       []string
		want       string
		confidence Confidence
	}{
		{"agreeing clues", Device{Name: "front-door-doorbell", Vendor: "Ring"}, []string{"ring"}, "doorbell", ConfidenceHigh},
		{"a strong name alone", Device{Name: "dock-camera-02"}, nil, "camera", ConfidenceMedium},
		{"a maker alone", Device{Vendor: "Sonos"}, nil, "speaker", ConfidenceMedium},
		{"services alone", Device{}, []string{"lg-webos"}, "tv", ConfidenceMedium},
		{"an e-ink display on a smart-home chip", Device{Vendor: "Espressif"}, []string{"trmnl"}, "smart-home", ConfidenceHigh},
		{"a pixel clock on a smart-home chip", Device{Vendor: "Espressif"}, []string{"tidbyt"}, "smart-home", ConfidenceHigh},
		{"a smart-home chip alone", Device{Vendor: "Espressif"}, nil, "smart-home", ConfidenceLow},
		{"a smart-home chip named as a plug", Device{Name: "desk-plug", Vendor: "Espressif"}, nil, "smart-plug", ConfidenceHigh},
		{"a generator's cloud alone", Device{}, []string{"generac"}, "smart-home", ConfidenceLow},
		{"a generator on a cellular module", Device{Vendor: "Telit"}, []string{"generac"}, "smart-home", ConfidenceHigh},
		{"a 3D printer's cloud alone", Device{}, []string{"bambu-lab"}, "printer", ConfidenceLow},
		{"a 3D printer on a radio module", Device{Vendor: "Quectel"}, []string{"bambu-lab"}, "printer", ConfidenceHigh},
		{"a slicer on a computer", Device{Vendor: "Dell"}, []string{"bambu-lab"}, "", ""},
		{"a module reaching a broker", Device{Vendor: "Espressif"}, []string{"mqtt"}, "smart-home", ConfidenceHigh},
		{"UniFi's own gear", Device{Name: "Basement U7 Pro", Vendor: "Ubiquiti", UniFiType: "network"}, nil, "network", ConfidenceHigh},
		{"an operator's type over UniFi's gear", Device{Vendor: "Ubiquiti", UniFiType: "network", Type: "storage"}, nil, "storage", ConfidenceSet},
		{"a UniFi NAS by its name", Device{Name: "Home-UNAS-4", Vendor: "Ubiquiti"}, nil, "storage", ConfidenceMedium},
		{"a UniFi NAS by UniFi's word", Device{Name: "Home-UNAS-4", Vendor: "Ubiquiti", UniFiType: "storage"}, nil, "storage", ConfidenceHigh},
		{"a type UniFi names that Sable lacks", Device{Vendor: "Ubiquiti", UniFiType: "ups"}, nil, "network", ConfidenceLow},
		{"an e-ink tablet by name and sync", Device{Name: "Remarkable 2", Vendor: "AMPAK"}, []string{"remarkable"}, "tablet", ConfidenceHigh},
		{"an e-ink tablet's sync alone", Device{}, []string{"remarkable"}, "tablet", ConfidenceLow},
		{"a weak lean", Device{Vendor: "Dell"}, nil, "computer", ConfidenceLow},
		{"an operator's type wins", Device{Name: "dock-camera-02", Type: "doorbell"}, nil, "doorbell", ConfidenceSet},
		{"no clues", Device{Name: "george"}, nil, "", ""},
		{"a toss-up", Device{Vendor: "Apple"}, nil, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			used := make([]services.Service, 0, len(test.used))
			for _, id := range test.used {
				used = append(used, service(t, id))
			}
			guess := Classify(test.device, used)
			if guess.Type != test.want || guess.Confidence != test.confidence {
				t.Fatalf("Classify = %q (%s), want %q (%s); reasons %+v", guess.Type, guess.Confidence, test.want, test.confidence, guess.Reasons)
			}
			if guess.Type != "" && len(guess.Reasons) == 0 {
				t.Fatal("a guess came without reasons")
			}
		})
	}
}

func TestClassifyKeepsOnlyTheReasonsThatSupportTheGuess(t *testing.T) {
	t.Parallel()
	guess := Classify(Device{Name: "front-door-doorbell", Vendor: "Ring"}, []services.Service{service(t, "ring"), service(t, "windows-update")})
	for _, reason := range guess.Reasons {
		if reason.Text == "Talks to Windows Update" {
			t.Fatalf("reasons include evidence for another type: %+v", guess.Reasons)
		}
	}
	if len(guess.Reasons) != 3 {
		t.Fatalf("reasons = %+v", guess.Reasons)
	}
}

func TestGuessesReadWithTheirCertainty(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		device Device
		want   string
	}{
		{Device{Vendor: "Ring", Guess: Guess{Type: "doorbell", Confidence: ConfidenceHigh}}, "A doorbell made by Ring. "},
		{Device{Guess: Guess{Type: "camera", Confidence: ConfidenceMedium}}, "Probably a camera. "},
		{Device{Vendor: "Dell", Guess: Guess{Type: "computer", Confidence: ConfidenceLow}}, "Made by Dell. "},
		{Device{Guess: Guess{Type: "game-console", Confidence: ConfidenceSet}}, "A game console. "},
		{Device{}, ""},
	} {
		if got := describeDevice(test.device); got != test.want {
			t.Errorf("describeDevice(%+v) = %q, want %q", test.device.Guess, got, test.want)
		}
	}
	if got := GuessText(Guess{Type: "thermostat", Confidence: ConfidenceLow}); got != "Maybe a thermostat" {
		t.Errorf("GuessText = %q", got)
	}
	// An acronym keeps its capitals in the middle of a sentence.
	if got := GuessText(Guess{Type: "tv", Confidence: ConfidenceMedium}); got != "Probably a TV" {
		t.Errorf("GuessText = %q", got)
	}
	if got := describeDevice(Device{Guess: Guess{Type: "tv", Confidence: ConfidenceHigh}, Vendor: "Samsung"}); got != "A TV made by Samsung. " {
		t.Errorf("describeDevice = %q", got)
	}
}

func TestClassifyRemembersWhatItDetectedUnderACorrection(t *testing.T) {
	t.Parallel()
	guess := Classify(Device{Name: "dock-camera-02", Type: "doorbell"}, nil)
	if guess.Type != "doorbell" || guess.Detected != "camera" {
		t.Fatalf("guess = %+v", guess)
	}
}

func TestMQTTNamesAreBrokersNotSites(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"mqtt.evrythng.com.":   true,
		"mqtt2.tidbyt.com":     true,
		"us.mqtt.bambulab.com": true,
		"mqtt.org":             false,
		"mqttfan.example":      false,
		"www.example.com":      false,
		"mqtt":                 false,
	} {
		if got := mqttName(name); got != want {
			t.Errorf("mqttName(%q) = %t, want %t", name, got, want)
		}
	}
}

// A device whose only lookups are its maker's MQTT broker and clock is smart
// home gear, even when Sable knows neither the maker nor the service.
func TestIdentifyCountsAnyMQTTBroker(t *testing.T) {
	t.Parallel()
	built := Build(Input{Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{{Client: "10.0.7.182", Queries: 40}}}})
	Identify(built, map[string][]string{"10.0.7.182": {"mqtt.evrythng.com", "time.evrythng.com"}})
	guess := built[0].Guess
	if guess.Type != "smart-home" || guess.Confidence != ConfidenceLow || len(guess.Reasons) != 1 || guess.Reasons[0].Text != "Talks to an MQTT server" {
		t.Fatalf("guess = %+v", guess)
	}
}
