package devices

import (
	"testing"

	"github.com/drudge/sable/internal/insights/services"
)

func service(t *testing.T, id string) services.Service {
	t.Helper()
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
}

func TestClassifyRemembersWhatItDetectedUnderACorrection(t *testing.T) {
	t.Parallel()
	guess := Classify(Device{Name: "dock-camera-02", Type: "doorbell"}, nil)
	if guess.Type != "doorbell" || guess.Detected != "camera" {
		t.Fatalf("guess = %+v", guess)
	}
}
