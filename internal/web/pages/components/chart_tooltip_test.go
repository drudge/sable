package components

import "testing"

func TestChartTooltipRendersHiddenReadingBox(t *testing.T) {
	t.Parallel()

	tests := []struct {
		props ChartTooltipProps
		want  string
	}{
		{ChartTooltipProps{}, `<div class="chart-tooltip" data-chart-tooltip aria-hidden="true" hidden></div>`},
		{ChartTooltipProps{Class: "donut-tooltip"}, `<div class="chart-tooltip donut-tooltip" data-chart-tooltip aria-hidden="true" hidden></div>`},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, ChartTooltip(test.props), ""); got != test.want {
			t.Errorf("got  %s\nwant %s", got, test.want)
		}
	}
}
