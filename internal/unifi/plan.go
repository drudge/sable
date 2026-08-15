package unifi

import "time"

// Status is the synchronizer state the console renders. It lives here rather
// than beside the reconciler so the web layer can read it without depending on
// the application wiring.
type Status struct {
	Enabled      bool
	Running      bool
	LastAttempt  time.Time
	LastSuccess  time.Time
	NextAttempt  time.Time
	Duration     time.Duration
	LastError    string
	Hosts        int
	ZonesCreated int
	Added        int
	Updated      int
	Removed      int
}

// Plan is the difference one synchronization would make. The setup wizard
// renders it as a preview and the reconciler applies it, so the review screen
// and the result cannot drift apart.
type Plan struct {
	CreatedZones []string
	Added        []PlanRecord
	Updated      []PlanRecord
	Removed      []PlanRecord
	// Publishing is the complete record set the mapping produces, whether or not
	// it differs from what is already there. Without it a review of an
	// already-synchronized setup would show nothing at all.
	Publishing []PlanRecord
	// Skipped explains every host or network that produced no record, so an
	// operator can tell "nothing to do" apart from "something went wrong".
	Skipped []string
	Hosts   int
}

// PlanRecord is one record a plan would add, change, or remove.
type PlanRecord struct {
	Zone  string
	Name  string
	Type  string
	Value string
}

// Empty reports whether applying the plan would change anything.
func (plan Plan) Empty() bool {
	return len(plan.CreatedZones) == 0 && len(plan.Added) == 0 && len(plan.Updated) == 0 && len(plan.Removed) == 0
}

// Changes totals the record mutations in the plan.
func (plan Plan) Changes() int {
	return len(plan.Added) + len(plan.Updated) + len(plan.Removed)
}
