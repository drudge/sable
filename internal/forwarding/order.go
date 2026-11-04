package forwarding

// The ways each query can pick among forwarders of one priority.
const (
	// OrderRoundRobin starts each query at the next forwarder in turn,
	// spreading the load evenly. It is the default.
	OrderRoundRobin = "round_robin"
	// OrderInOrder always starts at the first forwarder listed and moves down
	// the list only on failure, like dnsmasq's strict-order. It suits a list
	// ordered for privacy or filtering rather than speed.
	OrderInOrder = "in_order"
	// OrderFastest starts at the forwarder that has been answering fastest,
	// and now and then at the one that has gone longest without a query
	// instead, so a forwarder that got faster is noticed.
	OrderFastest = "fastest"
)

// Orders lists every order, the default first.
var Orders = []string{OrderRoundRobin, OrderInOrder, OrderFastest}
