package main

// isolationDoc states, on every room answer, what the room's placement does
// and does not isolate. A guest must never have to infer this from a hotel
// id. On a sealed hotel the TEE covers the hotel VM; rooms on that VM are
// separated by the room runtime only, and no room has its own attestation.
func isolationDoc(h *hotel, roomDoc map[string]any) map[string]any {
	labels := h.labels()
	sealed := h.cfg.Sealed || labels["sealed"] == "true"
	var tee any
	if sealed {
		tee = "amd_sev_snp"
		if t := labels["tee"]; t != "" {
			tee = t
		}
	}
	runtime, _ := roomDoc["runtime"].(string)
	if runtime == "" {
		// The hotel's room documents carry no runtime; the room kit reports
		// it in /room/health, which syncHotel stores.
		runtime = h.hotelRuntime()
	}
	if runtime == "" {
		runtime = "unknown"
	}
	mode := ""
	if net, ok := roomDoc["network"].(map[string]any); ok {
		mode, _ = net["mode"].(string)
	}
	return map[string]any{
		"hotel_sealed":        sealed,
		"hotel_tee":           tee,
		"room_runtime":        runtime,
		"attested_per_room":   false,
		"network_mode":        mode,
		"attestation_of_host": "/v1/hotels/" + h.cfg.ID + "/attestation",
	}
}

// hotelRuntime is the runtime the hotel last reported in /room/health, or "".
func (h *hotel) hotelRuntime() string {
	rt, _ := h.healthRuntime.Load().(string)
	return rt
}
