package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	reflect "reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/VictoriaMetrics/fastcache"
	xxhash "github.com/cespare/xxhash/v2"
	"github.com/coocood/freecache"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify-server/config"
	"github.com/sipcapture/heplify-server/sipparser"
)

// The first 4 bytes are the string "HEP3". The next 2 bytes are the length of the
// whole message (len("HEP3") + length of all the chunks we have. The next bytes
// are all the chunks created by makeChunks()
// Bytes: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31......
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        | "HEP3"|len|chunks(0x0001|0x0002|0x0003|0x0004|0x0007|0x0008|0x0009|0x000a|0x000b|......)
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

var (
	dedupCache            = fastcache.New(32 * 1024 * 1024)
	scriptCache           = fastcache.New(32 * 1024 * 1024)
	rtpCache              = freecache.NewCache(64 * 1024 * 1024)
	strBackslashQuote     = []byte(`\"`)
	strBackslashBackslash = []byte(`\\`)
	strBackslashN         = []byte(`\n`)
	strBackslashR         = []byte(`\r`)
	strBackslashT         = []byte(`\t`)
	strBackslashF         = []byte(`\u000c`)
	strBackslashB         = []byte(`\u0008`)
	strBackslashLT        = []byte(`\u003c`)
	strBackslashQ         = []byte(`\u0027`)
	strEmpty              = []byte(``)

	// TODO: Move it to utils
	contentTypeHeaderNames = [][]byte{
		[]byte("Content-Type"),
		[]byte("Content-type"),
		[]byte("content-type"),
		[]byte("CONTENT-TYPE"),
		[]byte("c"),
	}

	sdpMethods = map[string]bool{
		"UPDATE": true,
		"INVITE": true,
	}
)

// HEP chunks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
	NodeName  = 19 // Chunk 0x0013 NodeName
)

type DBValidator interface {
	ValidateFilterRules(fromUser, toUser string) bool
	InsertRTPBypass(h *HEP)
}

var defaultValidator DBValidator

type RTPHeaders struct {
	Version        uint8
	Padding        uint8
	Extension      uint8
	CC             uint8
	Marker         uint8
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	Ssrc           uint32
}

// HEP represents HEP packet
type HEP struct {
	Version     uint32 `protobuf:"varint,1,req,name=Version" json:"Version"`
	Protocol    uint32 `protobuf:"varint,2,req,name=Protocol" json:"Protocol"`
	SrcIP       string `protobuf:"bytes,3,req,name=SrcIP" json:"SrcIP"`
	DstIP       string `protobuf:"bytes,4,req,name=DstIP" json:"DstIP"`
	SrcPort     uint32 `protobuf:"varint,5,req,name=SrcPort" json:"SrcPort"`
	DstPort     uint32 `protobuf:"varint,6,req,name=DstPort" json:"DstPort"`
	Tsec        uint32 `protobuf:"varint,7,req,name=Tsec" json:"Tsec"`
	Tmsec       uint32 `protobuf:"varint,8,req,name=Tmsec" json:"Tmsec"`
	ProtoType   uint32 `protobuf:"varint,9,req,name=ProtoType" json:"ProtoType"`
	NodeID      uint32 `protobuf:"varint,10,req,name=NodeID" json:"NodeID"`
	NodePW      string `protobuf:"bytes,11,req,name=NodePW" json:"NodePW"`
	Payload     string `protobuf:"bytes,12,req,name=Payload" json:"Payload"`
	RTPHeaders  *RTPHeaders
	RTPPayload  []byte `json:"RTPPayload,omitempty"`
	CID         string `protobuf:"bytes,13,req,name=CID" json:"CID"`
	Vlan        uint32 `protobuf:"varint,14,req,name=Vlan" json:"Vlan"`
	ProtoString string
	Timestamp   time.Time
	SIP         *sipparser.SipMsg
	NodeName    string
	TargetName  string
	SID         string
}

func SetDbValidator(v DBValidator) {
	defaultValidator = v
}

// DecodeHEP returns a parsed HEP message
func DecodeHEP(packet []byte) (*HEP, error) {
	hep := &HEP{}
	err := hep.parse(packet)
	if err != nil {
		return nil, err
	}
	return hep, nil
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// Will add a srcIp+srcPort key and CID Value to the cache w 10 min expire time
// .Set from freecache is an upsert method, good cuz of reinvites or something like dat i guess
// not pretty sure just validate it later when its running
func cacheCall(srcIp []byte, srcPort []byte, callId []byte) {
	var buffer [60]byte
	key := append(append(append(buffer[:0], srcIp...), ' '), srcPort...)

	if err := rtpCache.Set(key, callId, 600); err != nil {
		logp.Err("Error inserting callId onto cache %v", err)
	}
}

func isCallCached(srcIp []byte, srcPort []byte) (bool, []byte) {
	var buffer [60]byte
	key := append(append(append(buffer[:0], srcIp...), ' '), srcPort...)

	callId, err := rtpCache.Get(key)
	if err != nil {
		return false, nil
	}
	return true, callId
}

func validateSDP(payload string, callId string) {
	bytePayload := []byte(payload)
	byteCallId := []byte(callId)

	// Do we have a header separator?
	posHeaderEnd := bytes.Index(bytePayload, []byte("\r\n\r\n"))
	if posHeaderEnd < 0 {
		return
	}
	headers := bytePayload[:posHeaderEnd+4] // keep separator
	content := bytePayload[posHeaderEnd+4:] // strip separator

	// Do we have SDP content?
	contentType, err := getHeaderValue(contentTypeHeaderNames, headers)
	if err != nil {
		// Content-Type only exists if there is content, no need for logging.
		return
	}

	if !bytes.HasPrefix(contentType, []byte("application/sdp")) {
		return
	}

	var (
		posLine    = 0    // start of line.
		posLineEnd = 0    // end of line, position of \n or end of content.
		session    = true // in session or multimedia?
		sessionIP  []byte // IP found in session connection.
		rtpIP      []byte // IP for RTP.
		rtpPort    []byte // port for RTP.
	)

sdpLoop:
	for posLine = 0; posLine < len(content); posLine = posLineEnd + 1 {
		// Find \n at end of line.
		posLineEnd = posLine + bytes.Index(content[posLine:], []byte("\n"))
		if posLineEnd < posLine {
			posLineEnd = len(content)
		}
		// Get line without line separator, remove \r.
		line := content[posLine:posLineEnd]
		if bytes.HasSuffix(line, []byte("\r")) {
			line = line[:len(line)-1]
		}

		// Skip lines that do not look like SDP.
		if len(line) < 2 || line[1] != '=' {
			// Multipart content contains non SDP lines, do not clutter the log.
			logp.Debug("sdp", "Fishy sdp line %q. callID=%q", line, byteCallId)
			continue sdpLoop
		}

		// Process SDP line.
		switch line[0] {
		case 'c':
			// Connection line should contain at least
			// "c=IN IP4 1.1.1.1" or "c=IN IP6 1111::".
			if !bytes.HasPrefix(line, []byte("c=IN IP")) || len(line) < 16 {
				logp.Debug("sdp", "Fishy c= line %q. callID=%q", line, byteCallId)
				continue sdpLoop
			}
			// Extract IP.
			ip := line[9:]
			// Check for and strip ttl/count separated by slash.
			sep := bytes.Index(ip, []byte("/"))
			if sep > 0 {
				ip = ip[:sep]
			}
			// Use as session or RTCP IP.
			if session {
				sessionIP = ip
			} else {
				rtpIP = ip
			}
		case 'm':
			// Begin new media.
			// No longer session.
			session = false
			// Add keys for previous media.
			if len(rtpIP) > 0 && len(rtpPort) > 0 {
				cacheCall(rtpIP, rtpPort, byteCallId)
			}
			// Reset RTP data for this media.
			rtpIP = sessionIP
			rtpPort = nil
			// We are only interested in audio.
			if !bytes.HasPrefix(line, []byte("m=audio ")) {
				continue sdpLoop
			}
			// Find separator after RTP port number.
			sep := bytes.Index(line[8:], []byte(" "))
			if sep < 4 { // Port should be above 1000
				logp.Debug("sdp", "Fishy m=audio line %q. callID=%q", line, byteCallId)
				continue sdpLoop
			}
			// Extract RTP port.
			rtpPort = line[8 : 8+sep]
		default:
			// ignore other SDP lines.
		}
	}
	if len(rtpIP) > 0 && len(rtpPort) > 0 {
		cacheCall(rtpIP, rtpPort, byteCallId)
	}
}

func validateUserInDB(fromUser string, toUser string) bool {
	if defaultValidator == nil {
		return false
	}
	return defaultValidator.ValidateFilterRules(fromUser, toUser)
}

func insertRTP(h *HEP) {
	defaultValidator.InsertRTPBypass(h)
}

// Stolen from heplify
// TODO: move to utils
func getHeaderValue(headerNames [][]byte, data []byte) ([]byte, error) {
	var startPos int = -1
	var headerName []byte
	var buffer [60]byte // use large enough buffer for header name and separators on stack for fast append
	var search []byte
	for hederNameIdx := range headerNames {
		headerName = headerNames[hederNameIdx]
		// Check if first header.
		if bytes.HasPrefix(data, headerName) {
			if len(data) > len(headerName) && data[len(headerName)] == ':' {
				startPos = 0
				break
			}
		}
		// Check if other header.
		search = append(append(append(buffer[:0], '\r', '\n'), headerName...), ':')
		startPos = bytes.Index(data, search)
		if startPos >= 0 {
			// Skip new line
			startPos += 2
			break
		}
	}
	if startPos < 0 {
		return nil, errors.New("no such header")
	}
	endPos := bytes.Index(data[startPos:], []byte("\r\n"))
	if endPos < 0 {
		return nil, errors.New("no such header")
	}
	return bytes.TrimSpace(data[startPos+len(headerName)+1 : startPos+endPos]), nil
}

// This block up here can be thrown into a correlator.go lately
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

func (h *HEP) parse(packet []byte) error {
	var err error
	if bytes.HasPrefix(packet, []byte{0x48, 0x45, 0x50, 0x33}) {
		err = h.parseHEP(packet)
		if err != nil {
			logp.Warn("%v", err)
			return err
		}
	} else if config.Setting.HEPv2Enable && (bytes.HasPrefix(packet, []byte{0x1}) || bytes.HasPrefix(packet, []byte{0x2})) {
		err = h.parseHEP2(packet)
		if err != nil {
			logp.Warn("bad HEPv1/v2 decoding: %v", err)
			return err
		}
	} else {
		err = h.Unmarshal(packet)
		if err != nil {
			logp.Warn("malformed packet with length %d which is neither hep nor protobuf encapsulated", len(packet))
			return err
		}
	}

	h.Timestamp = time.Unix(int64(h.Tsec), int64(h.Tmsec*1000))
	if h.Tsec == 0 && h.Tmsec == 0 {
		logp.Debug("hep", "got null timestamp from nodeID %d", h.NodeID)
		h.Timestamp = time.Now()
	}

	h.normPayload()
	if h.ProtoType == 0 {
		return nil
	}

	if h.ProtoType == 1 && len(h.Payload) > 32 {
		err = h.parseSIP()
		if err != nil {
			logp.Warn("%v\n%q\nnodeID: %d, protoType: %d, version: %d, protocol: %d, length: %d, flow: %s:%d->%s:%d\n\n",
				err, h.Payload, h.NodeID, h.ProtoType, h.Version, h.Protocol, len(h.Payload), h.SrcIP, h.SrcPort, h.DstIP, h.DstPort)
			return err
		}

		//Is a possible SDP method? if it is go through extracting the media endpoint
		//UPDATE and INVITE
		if sdpMethods[h.SIP.CseqMethod] {
			if validateUserInDB(h.SIP.FromUser, h.SIP.ToUser) {
				validateSDP(h.Payload, h.SIP.CallID)
			}
		}

		for _, m := range config.Setting.CensorMethod {
			if m == h.SIP.CseqMethod {
				lb := len(h.SIP.Body)
				h.SIP.Body = strings.Repeat("x", lb)
				h.Payload = h.Payload[:len(h.Payload)-lb] + h.SIP.Body
			}
		}

		if len(config.Setting.DiscardMethod) > 0 {
			for k := range config.Setting.DiscardMethod {
				if config.Setting.DiscardMethod[k] == h.SIP.CseqMethod {
					h.ProtoType = 0
					return nil
				}
			}
		}
	}
	if h.ProtoType == 7 && len(h.RTPPayload) > 12 && h.RTPPayload[0] == 0x80 {
		byteSrcIp := []byte(h.SrcIP)
		strSrcPort := strconv.Itoa(int(h.SrcPort))
		byteSrcPort := []byte(strSrcPort)

		isCached, CID := isCallCached(byteSrcIp, byteSrcPort)
		if isCached {
			h.CID = string(CID)
			err = h.parseRTP()
			if err != nil {
				logp.Warn("%v\n%q\nnodeID: %d, protoType: %d, version: %d, protocol: %d, flow: %s:%d->%s:%d\n\n",
					err, h.Payload, h.NodeID, h.ProtoType, h.Version, h.Protocol, h.SrcIP, h.SrcPort, h.DstIP, h.DstPort)
				return err
			}
			insertRTP(h)
			h.ProtoType = 0
		} else {
			//if not cached wont store the RTP packet
			h.ProtoType = 0
			return nil
		}
	}

	if h.NodeName == "" {
		h.NodeName = strconv.FormatUint(uint64(h.NodeID), 10)
	}

	logp.Debug("hep", "%+v\n\n", h)
	return nil
}

func (h *HEP) normPayload() {
	if config.Setting.Dedup {
		ts := uint64(h.Timestamp.UnixNano())
		kh := make([]byte, 8)
		ks := xxhash.Sum64String(h.Payload)
		binary.BigEndian.PutUint64(kh, ks)

		if buf := dedupCache.Get(nil, kh); buf != nil {
			i := binary.BigEndian.Uint64(buf)
			d := ts - i
			if i > ts {
				d = i - ts
			}
			if d < 500e6 {
				h.ProtoType = 0
				return
			}
		}

		tb := make([]byte, 8)
		binary.BigEndian.PutUint64(tb, ts)
		dedupCache.Set(kh, tb)
	}

	h.Payload = toUTF8(h.Payload, "")
}

func (h *HEP) EscapeFields(w io.Writer, tag string) (int, error) {
	switch tag {
	case "callid":
		return WriteJSONString(w, h.SIP.CallID)
	case "cseq":
		return WriteJSONString(w, h.SIP.CseqVal)
	case "method":
		return WriteJSONString(w, h.SIP.FirstMethod)
	case "ruri_user":
		return WriteJSONString(w, h.SIP.URIUser)
	case "ruri_domain":
		return WriteJSONString(w, h.SIP.URIHost)
	case "from_user":
		return WriteJSONString(w, h.SIP.FromUser)
	case "from_domain":
		return WriteJSONString(w, h.SIP.FromHost)
	case "from_tag":
		return WriteJSONString(w, h.SIP.FromTag)
	case "to_user":
		return WriteJSONString(w, h.SIP.ToUser)
	case "to_domain":
		return WriteJSONString(w, h.SIP.ToHost)
	case "to_tag":
		return WriteJSONString(w, h.SIP.ToTag)
	case "via":
		return WriteJSONString(w, h.SIP.ViaOne)
	case "contact_user":
		return WriteJSONString(w, h.SIP.ContactUser)
	case "contact_domain":
		return WriteJSONString(w, h.SIP.ContactHost)
	case "user_agent":
		return WriteJSONString(w, h.SIP.UserAgent)
	case "pid_user":
		return WriteJSONString(w, h.SIP.PaiUser)
	case "auth_user":
		return WriteJSONString(w, h.SIP.AuthUser)
	case "server":
		return WriteJSONString(w, h.SIP.Server)
	case "content_type":
		return WriteJSONString(w, h.SIP.ContentType)
	case "reason":
		return WriteJSONString(w, h.SIP.ReasonVal)
	case "diversion":
		return WriteJSONString(w, h.SIP.DiversionVal)
	case "expires":
		return WriteJSONString(w, h.SIP.Expires)
	case "callid_aleg":
		return WriteJSONString(w, h.SIP.XCallID)
	default:
		return w.Write(strEmpty)
	}
}

func WriteJSONString(w io.Writer, s string) (int, error) {
	write := w.Write
	b := stb(s)
	j := 0
	n := len(b)
	if n > 0 {
		// Hint the compiler to remove bounds checks in the loop below.
		_ = b[n-1]
	}
	for i := 0; i < n; i++ {
		switch b[i] {
		case '"':
			write(b[j:i])
			write(strBackslashQuote)
			j = i + 1
		case '\\':
			write(b[j:i])
			write(strBackslashBackslash)
			j = i + 1
		case '\n':
			write(b[j:i])
			write(strBackslashN)
			j = i + 1
		case '\r':
			write(b[j:i])
			write(strBackslashR)
			j = i + 1
		case '\t':
			write(b[j:i])
			write(strBackslashT)
			j = i + 1
		case '\f':
			write(b[j:i])
			write(strBackslashF)
			j = i + 1
		case '\b':
			write(b[j:i])
			write(strBackslashB)
			j = i + 1
		default:
			if b[i] < 32 {
				write(b[j:i])
				fmt.Fprintf(w, "\\u%0.4x", b[i])
				j = i + 1
				continue
			}
		}
	}
	return write(b[j:])
}

func stb(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var res []byte

	bh := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return res
}

func toUTF8(s, replacement string) string {
	var b strings.Builder

	for i, c := range s {
		if c != utf8.RuneError && c != '\x00' {
			continue
		}

		_, wid := utf8.DecodeRuneInString(s[i:])
		if wid == 1 {
			b.Grow(len(s) + len(replacement))
			b.WriteString(s[:i])
			s = s[i:]
			break
		}
	}

	// Fast path for unchanged input
	if b.Cap() == 0 { // didn't call b.Grow above
		return s
	}

	invalid := false // previous byte was from an invalid UTF-8 sequence
	for i := 0; i < len(s); {
		c := s[i]
		if c == '\x00' {
			i++
			invalid = false
			continue
		} else if c < utf8.RuneSelf {
			i++
			invalid = false
			b.WriteByte(c)
			continue
		}
		_, wid := utf8.DecodeRuneInString(s[i:])
		if wid == 1 {
			i++
			if !invalid {
				invalid = true
				b.WriteString(replacement)
			}
			continue
		}
		invalid = false
		b.WriteString(s[i : i+wid])
		i += wid
	}

	return b.String()
}
