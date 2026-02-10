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

	err := h.acmeChallengeProvider.Present(name, "", setDNSReq.Value)
	if err != nil {
		return nil, err
	}

	return &tailcfg.SetDNSResponse{}, nil
}
