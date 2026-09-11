package update

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ContainerWebUpdatesEnvironment opts Docker deployments into installation and
// managed restarts. Operators must configure the container's restart policy.
const ContainerWebUpdatesEnvironment = "SABLE_WEB_UPDATES"

// ContainerWebUpdatesEnabled shares the opt-in between the immutable launcher
// and staged releases, including releases launched by older container images.
func ContainerWebUpdatesEnabled() (bool, error) {
	value := strings.TrimSpace(os.Getenv(ContainerWebUpdatesEnvironment))
	if value == "" {
		return false, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", ContainerWebUpdatesEnvironment)
	}
	return enabled, nil
}
