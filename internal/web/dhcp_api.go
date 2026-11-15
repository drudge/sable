package web

import (
	"net/http"

	"github.com/drudge/sable/internal/config"
)

// dhcpSettingsLimit caps a PUT of the whole [dhcp] section: room for a few
// thousand reservations.
const dhcpSettingsLimit = 1 << 20

func (server *Server) dhcpAPI(writer http.ResponseWriter, request *http.Request) {
	state, err := server.dhcpService().State(requestActor(request, ""))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, state)
}

func (server *Server) saveDHCPAPI(writer http.ResponseWriter, request *http.Request) {
	var settings config.DHCP
	if err := decodeJSON(request, &settings); err != nil {
		apiError(writer, http.StatusBadRequest, "the body must be the DHCP settings as JSON")
		return
	}
	who := requestActor(request, "")
	if err := server.dhcpService().Save(request.Context(), who, settings); err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	server.dhcpAPI(writer, request)
}

func (server *Server) dhcpLeasesAPI(writer http.ResponseWriter, request *http.Request) {
	leases, err := server.dhcpService().Leases(request.Context(), requestActor(request, ""), request.URL.Query().Get("scope"))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"leases": leases})
}

func (server *Server) removeDHCPLeaseAPI(writer http.ResponseWriter, request *http.Request) {
	err := server.dhcpService().RemoveLease(request.Context(), requestActor(request, ""), request.PathValue("address"))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// reserveDHCPLeaseAPI takes an optional body naming the reservation.
func (server *Server) reserveDHCPLeaseAPI(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Name    string `json:"name"`
		Comment string `json:"comment"`
	}
	if request.ContentLength != 0 {
		if err := decodeJSON(request, &input); err != nil {
			apiError(writer, http.StatusBadRequest, "the body must be JSON with name and comment")
			return
		}
	}
	reservation, err := server.dhcpService().Reserve(request.Context(), requestActor(request, ""), request.PathValue("address"), input.Name, input.Comment)
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, reservation)
}

func (server *Server) setDHCPReservationAPI(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Address string `json:"address"`
		Name    string `json:"name"`
		Comment string `json:"comment"`
	}
	if err := decodeJSON(request, &input); err != nil {
		apiError(writer, http.StatusBadRequest, "the body must be JSON with address, name, and comment")
		return
	}
	reservation, err := server.dhcpService().SetReservation(request.Context(), requestActor(request, ""), request.PathValue("scope"), config.DHCPReservation{
		MAC: request.PathValue("mac"), Address: input.Address, Name: input.Name, Comment: input.Comment,
	})
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, reservation)
}

func (server *Server) removeDHCPReservationAPI(writer http.ResponseWriter, request *http.Request) {
	err := server.dhcpService().RemoveReservation(request.Context(), requestActor(request, ""), request.PathValue("scope"), request.PathValue("mac"))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}
