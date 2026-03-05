package hscontrol

import (
	"context"
	"strings"

	"tailscale.com/tailcfg"
)

func (h *Headscale) handleSetDNS(
	_ context.Context,
	setDNSReq tailcfg.SetDNSRequest,
) (*tailcfg.SetDNSResponse, error) {
	name := strings.TrimPrefix(setDNSReq.Name, "_acme-challenge.")

	err := h.certSolver.challengeProvider.Present(name, "", setDNSReq.Value)
	if err != nil {
		return nil, err
	}

	err = h.certSolver.stubResolver.CheckDNSPropagation(setDNSReq.Name, setDNSReq.Value)

	return &tailcfg.SetDNSResponse{}, nil
}
