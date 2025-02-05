package decoder

import (
	"github.com/negbie/logp"
)

func (h *HEP) parseRTP() error {
	h.RTPPayload, h.RTPHeaders = parsePayload(h.RTPPayload)

	logp.Info("Version %d", h.RTPHeaders.Version)
	logp.Info("Padding %d", h.RTPHeaders.Padding)
	logp.Info("Extension %d", h.RTPHeaders.Extension)
	logp.Info("CC %d", h.RTPHeaders.CC)
	logp.Info("Marker %d", h.RTPHeaders.Marker)
	logp.Info("PayloadType %d", h.RTPHeaders.PayloadType)
	logp.Info("SeqNumber %d", h.RTPHeaders.SequenceNumber)
	logp.Info("Timestamp %d", h.RTPHeaders.Timestamp)
	logp.Info("SSRC %d", h.RTPHeaders.Ssrc)
	logp.Info("\n%x", h.RTPPayload)
	return nil
}

func parsePayload(RTPPayload []byte) ([]byte, *RTPHeaders) {
	//RTP header size(12 bytes)
	if len(RTPPayload) < 12 {
		return nil, nil
	}

	headers := &RTPHeaders{}

	//first byte contains Version(2 bits), Padding(1 bit)
	//Extension(1 bit) and CC(4 bits)
	headers.Version = (RTPPayload[0] >> 6) & 0x03
	headers.Padding = (RTPPayload[0] >> 5) & 0x01
	headers.Extension = (RTPPayload[0] >> 4) & 0x01
	headers.CC = RTPPayload[0] & 0x0F

	//second byte contains Maker(1 bit) and PayloadType(7 bits)
	headers.Marker = (RTPPayload[1] >> 7) & 0x01
	headers.PayloadType = RTPPayload[1] & 0x7F

	//SequenceNumber(2 bytes)
	headers.SequenceNumber = uint16(RTPPayload[2])<<8 | uint16(RTPPayload[3])

	//Timestamp(4 bytes)
	headers.Timestamp = uint32(RTPPayload[4])<<24 |
		uint32(RTPPayload[5])<<16 |
		uint32(RTPPayload[6])<<8 |
		uint32(RTPPayload[7])

	//SSRC(4 bytes)
	headers.Ssrc = uint32(RTPPayload[8])<<24 |
		uint32(RTPPayload[9])<<16 |
		uint32(RTPPayload[10])<<8 |
		uint32(RTPPayload[11])

	payload := RTPPayload[12:]
	return payload, headers
}
