package database

import (
	"database/sql"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	_ "github.com/lib/pq"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify-server/config"
	"github.com/sipcapture/heplify-server/decoder"
	"github.com/valyala/bytebufferpool"
)

type Postgres struct {
	db              *sql.DB
	dbTimer         time.Duration
	bulkCnt         int
	forceHEPPayload []int

	currentCalls int64
	saveInterval time.Duration
	stopChan     chan struct{}
}

type CallRecord struct {
	CallID     string
	CreateDate time.Time
	StartDate  time.Time
	EndDate    time.Time
	Caller     string
	Callee     string
	SIPStatus  string
}

type HistoryPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	ConcurrentCalls int64     `json:"concurrent_calls"`
}

var (
	briefCache = freecache.NewCache(64 * 1024 * 1024)

	startMethods = map[string]bool{
		"INVITE": true,
	}

	endMethods = map[string]bool{
		"BYE":    true,
		"CANCEL": true,
	}
)

const (
	callCopy     = "COPY hep_proto_1_call(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	registerCopy = "COPY hep_proto_1_registration(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	defaultCopy  = "COPY hep_proto_1_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	rtcpCopy     = "COPY hep_proto_5_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	rtpCopy      = "COPY hep_proto_7_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	reportCopy   = "COPY hep_proto_35_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	dnsCopy      = "COPY hep_proto_53_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	isupCopy     = "COPY hep_proto_54_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
	logCopy      = "COPY hep_proto_100_default(sid,create_date,protocol_header,data_header,raw) FROM STDIN"
)

func (p *Postgres) setup() error {
	cs, err := ConnectString(config.Setting.DBDataTable)
	if err != nil {
		return err
	}

	if p.db, err = sql.Open(config.Setting.DBDriver, cs); err != nil {
		p.db.Close()
		return err
	}

	if err = p.db.Ping(); err != nil {
		p.db.Close()
		return err
	}

	p.db.SetMaxOpenConns(config.Setting.DBWorker * 4)
	p.db.SetMaxIdleConns(config.Setting.DBWorker)

	p.bulkCnt = config.Setting.DBBulk

	/* force JSON payload to data header */
	p.forceHEPPayload = config.Setting.ForceHEPPayload

	if p.bulkCnt < 1 {
		p.bulkCnt = 1
	}
	p.dbTimer = time.Duration(config.Setting.DBTimer) * time.Second

	decoder.SetDbValidator(p)

	p.InitCallCounter(30 * time.Second)

	logp.Info("%s connection established\n", config.Setting.DBDriver)
	return nil
}

func (p *Postgres) ValidateFilterRules(fromUser, toUser string) bool {
	var exists bool
	if len(fromUser) > 1 {
		if strings.HasPrefix(fromUser, "0") {
			fromUser = strings.TrimPrefix(fromUser, "0")
		}
	}
	if len(toUser) > 1 {
		if strings.HasPrefix(toUser, "0") {
			toUser = strings.TrimPrefix(toUser, "0")
		}
	}

	searchTo := "%" + toUser + "%"
	searchFrom := "%" + fromUser + "%"
	err := p.db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM filter_rules WHERE from_user like $1 or to_user like $2)",
		searchFrom,
		searchTo,
	).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}

func (p *Postgres) InitCallCounter(saveInterval time.Duration) {
	logp.Info("iniciou counter")
	p.saveInterval = saveInterval
	p.stopChan = make(chan struct{})

	p.loadCurrentCallCount()

	go p.periodicalCallCountSave()
}

func (p *Postgres) loadCurrentCallCount() {
	var lastCount int64
	err := p.db.QueryRow(`
		SELECT concurrent_calls
		FROM concurrent_calls_history
		ORDER BY timestamp DESC
		LIMIT 1
	`).Scan(&lastCount)

	if err != nil && err != sql.ErrNoRows {
		logp.Critical("Error loading concurrent_calls: %v", err)
		return
	}

	atomic.StoreInt64(&p.currentCalls, lastCount)
}

func (p *Postgres) IncrementCallCounter() {
	atomic.AddInt64(&p.currentCalls, 1)
}

func (p *Postgres) DecrementCallCounter() {
	current := atomic.AddInt64(&p.currentCalls, -1)
	if current < 0 {
		atomic.StoreInt64(&p.currentCalls, 0)
	}
}

func (p *Postgres) GetCurrentCallCounter() int64 {
	return atomic.LoadInt64(&p.currentCalls)
}

func (p *Postgres) saveCurrentCallCount() error {
	currentCount := atomic.LoadInt64(&p.currentCalls)

	_, err := p.db.Exec(`
		INSERT INTO concurrent_calls_history (concurrent_calls, timestamp)
		VALUES ($1, NOW())
	`, currentCount)

	if err != nil {
		return err
	}

	return nil
}

func (p *Postgres) periodicalCallCountSave() {
	ticker := time.NewTicker(p.saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.saveCurrentCallCount()
		case <-p.stopChan:
			p.saveCurrentCallCount()
		}
	}
}

func (p *Postgres) InsertRTPBypass(h *decoder.HEP) {
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)
	pHeader := makeProtoHeader(h, bb)
	dHeader := makeRTPDataHeader(h, bb)
	date := h.Timestamp.Format(time.RFC3339Nano)
	p.insertRTP(h.CID, date, pHeader, dHeader, h.RTPPayload)
}

func (p *Postgres) parseHEPtoCallRecord(pkt *decoder.HEP) *CallRecord {
	now := time.Now()
	callRecord := &CallRecord{
		CallID:     pkt.SID,
		CreateDate: now,
		StartDate:  pkt.Timestamp,
		EndDate:    pkt.Timestamp,
		Caller:     pkt.SIP.FromUser,
		Callee:     pkt.SIP.ToUser,
		SIPStatus:  pkt.SIP.FirstResp,
	}
	return callRecord
}

func isErrorResponse(resp string) bool {
	return strings.HasPrefix(resp, "4") ||
		strings.HasPrefix(resp, "5") ||
		strings.HasPrefix(resp, "6")
}

func (p *Postgres) insert(hCh chan *decoder.HEP) {
	var (
		callCnt, regCnt, defCnt, dnsCnt, logCnt, rtcpCnt, isupCnt, reportCnt, briefStartCnt, briefEndCnt int

		callRows       = make([]string, 0, p.bulkCnt)
		regRows        = make([]string, 0, p.bulkCnt)
		defRows        = make([]string, 0, p.bulkCnt)
		dnsRows        = make([]string, 0, p.bulkCnt)
		logRows        = make([]string, 0, p.bulkCnt)
		isupRows       = make([]string, 0, p.bulkCnt)
		rtcpRows       = make([]string, 0, p.bulkCnt)
		reportRows     = make([]string, 0, p.bulkCnt)
		briefStartRows = make([]CallRecord, 0, p.bulkCnt)
		briefEndRows   = make([]CallRecord, 0, p.bulkCnt)
		maxWait        = p.dbTimer
	)

	timer := time.NewTimer(maxWait)
	stop := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	defer stop()

	t := buildTemplate()
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	for {
		select {
		case pkt, ok := <-hCh:
			if !ok {
				if p.db != nil {
					p.db.Close()
				}
				return
			}

			date := pkt.Timestamp.Format(time.RFC3339Nano)

			if pkt.ProtoType == 1 && pkt.Payload != "" && pkt.SIP != nil {
				pHeader := makeProtoHeader(pkt, bb)
				dHeader := makeSIPDataHeader(pkt, bb, t)
				switch pkt.SIP.Profile {
				case "call":

					// BYE, CANCEL 3xx, 4xx, 5xx or 6xx to write in brief table
					if isErrorResponse(pkt.SIP.FirstResp) || endMethods[pkt.SIP.FirstMethod] {
						cr := p.parseHEPtoCallRecord(pkt)
						briefEndRows = append(briefEndRows, *cr)
						briefEndCnt++
						p.DecrementCallCounter()
						if true {
							p.briefBulkEnd(briefEndRows)
							briefEndRows = []CallRecord{}
							// briefEndCnt = 0
						}
						// INVITE brief table
					} else if startMethods[pkt.SIP.FirstMethod] {
						cr := p.parseHEPtoCallRecord(pkt)
						briefStartRows = append(briefStartRows, *cr)
						briefStartCnt++
						p.IncrementCallCounter()
						if true {
							p.briefBulkStart(briefStartRows)
							briefStartRows = []CallRecord{}
							//briefStartCnt = 0
						}
					}

					callRows = append(callRows, pkt.SID, date, pHeader, dHeader, pkt.Payload)
					callCnt++
					if callCnt == p.bulkCnt {
						p.bulkInsert(callCopy, callRows)
						callRows = []string{}
						callCnt = 0
					}
				case "registration":
					regRows = append(regRows, pkt.SID, date, pHeader, dHeader, pkt.Payload)
					regCnt++
					if regCnt == p.bulkCnt {
						p.bulkInsert(registerCopy, regRows)
						regRows = []string{}
						regCnt = 0
					}
				default:
					defRows = append(defRows, pkt.SID, date, pHeader, dHeader, pkt.Payload)
					defCnt++
					if defCnt == p.bulkCnt {
						p.bulkInsert(defaultCopy, defRows)
						defRows = []string{}
						defCnt = 0
					}
				}
			} else if pkt.ProtoType == 54 && pkt.Payload != "" {
				pHeader := makeProtoHeader(pkt, bb)
				sid, dHeader := makeISUPDataHeader([]byte(pkt.Payload), bb)

				isupRows = append(isupRows, sid, date, pHeader, dHeader, pkt.Payload)
				isupCnt++
				if isupCnt == p.bulkCnt {
					p.bulkInsert(isupCopy, isupRows)
					isupRows = []string{}
					isupCnt = 0
				}
			} else if pkt.ProtoType == 7 && pkt.RTPPayload != nil {
				pHeader := makeProtoHeader(pkt, bb)
				dHeader := makeRTPDataHeader(pkt, bb)
				p.insertRTP(pkt.CID, date, pHeader, dHeader, pkt.RTPPayload)
			} else if pkt.ProtoType >= 2 && pkt.Payload != "" && pkt.CID != "" && pkt.ProtoType != 7 {
				pHeader := makeProtoHeader(pkt, bb)
				dHeader := makeRTCDataHeader(pkt, bb)
				switch pkt.ProtoType {
				case 5:
					rtcpRows = append(rtcpRows, pkt.CID, date, pHeader, dHeader, pkt.Payload)
					rtcpCnt++
					if rtcpCnt == p.bulkCnt {
						p.bulkInsert(rtcpCopy, rtcpRows)
						rtcpRows = []string{}
						rtcpCnt = 0
					}
				case 53:
					dnsRows = append(dnsRows, pkt.CID, date, pHeader, dHeader, pkt.Payload)
					dnsCnt++
					if dnsCnt == p.bulkCnt {
						p.bulkInsert(dnsCopy, dnsRows)
						dnsRows = []string{}
						dnsCnt = 0
					}
				case 100:
					logRows = append(logRows, pkt.CID, date, pHeader, dHeader, pkt.Payload)
					logCnt++
					if logCnt == p.bulkCnt {
						p.bulkInsert(logCopy, logRows)
						logRows = []string{}
						logCnt = 0
					}
				default:
					stop()
					timer.Reset(1e9)
					var ForcePayload = false

					for _, v := range p.forceHEPPayload {
						if pkt.ProtoType == uint32(v) {
							ForcePayload = true
							break
						}
					}

					if ForcePayload {
						reportRows = append(reportRows, pkt.CID, date, pHeader, pkt.Payload, dHeader)
					} else {
						reportRows = append(reportRows, pkt.CID, date, pHeader, dHeader, pkt.Payload)
					}

					reportCnt++
					if reportCnt == p.bulkCnt {
						p.bulkInsert(reportCopy, reportRows)
						reportRows = []string{}
						reportCnt = 0
					}
				}
			}
		case <-timer.C:
			timer.Reset(maxWait)
			if callCnt > 0 {
				l := len(callRows)
				p.bulkInsert(callCopy, callRows[:l])
				callRows = []string{}
				callCnt = 0
			}
			if regCnt > 0 {
				l := len(regRows)
				p.bulkInsert(registerCopy, regRows[:l])
				regRows = []string{}
				regCnt = 0
			}
			if defCnt > 0 {
				l := len(defRows)
				p.bulkInsert(defaultCopy, defRows[:l])
				defRows = []string{}
				defCnt = 0
			}
			if rtcpCnt > 0 {
				l := len(rtcpRows)
				p.bulkInsert(rtcpCopy, rtcpRows[:l])
				rtcpRows = []string{}
				rtcpCnt = 0
			}
			if reportCnt > 0 {
				l := len(reportRows)
				p.bulkInsert(reportCopy, reportRows[:l])
				reportRows = []string{}
				reportCnt = 0
			}
			if dnsCnt > 0 {
				l := len(dnsRows)
				p.bulkInsert(dnsCopy, dnsRows[:l])
				dnsRows = []string{}
				dnsCnt = 0
			}
			if logCnt > 0 {
				l := len(logRows)
				p.bulkInsert(logCopy, logRows[:l])
				logRows = []string{}
				logCnt = 0
			}
			if isupCnt > 0 {
				l := len(isupRows)
				p.bulkInsert(isupCopy, isupRows[:l])
				isupRows = []string{}
				isupCnt = 0
			}
		}
	}
}

func (p *Postgres) briefBulkStart(rows []CallRecord) {
	if len(rows) == 0 {
		return
	}

	query := `INSERT INTO hep_brief_call_records (
		sid, create_date, start_date, end_date, caller, callee, sip_status
	) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	tx, err := p.db.Begin()
	if err != nil || tx == nil {
		logp.Err("%v", err)
		return
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		logp.Err("%v", err)
		err := tx.Rollback()
		if err != nil {
			logp.Err("%v", err)
		}
		return
	}

	for _, row := range rows {
		// Check if the call is on the cache
		// If true it's a sign that it already been written
		r, _ := briefCache.Get([]byte(row.CallID))
		if r != nil {
			continue
		} else {
			_, err = stmt.Exec(
				row.CallID,
				row.CreateDate,
				row.StartDate,
				row.EndDate,
				row.Caller,
				row.Callee,
				row.SIPStatus,
			)
			if err != nil {
				logp.Err("%v", err)
				continue
			}
			if err := briefCache.Set([]byte(row.CallID), []byte("yes"), 600); err != nil {
				logp.Err("Error inserting callId onto cache %v", err)
			}
		}
	}

	err = stmt.Close()
	if err != nil {
		logp.Err("%v", err)
	}

	err = tx.Commit()
	if err != nil {
		logp.Err("%v", err)
	}

	logp.Debug("sql", "%s\n\n%v\n\n", query, rows)
}

func (p *Postgres) briefBulkEnd(rows []CallRecord) {
	if len(rows) == 0 {
		return
	}

	query := `UPDATE hep_brief_call_records
		SET end_date = $2,
				sip_status = $3
		WHERE sid = $1`

	tx, err := p.db.Begin()
	if err != nil || tx == nil {
		logp.Err("%v", err)
		return
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		logp.Err("%v", err)
		err := tx.Rollback()
		if err != nil {
			logp.Err("%v", err)
		}
		return
	}

	for _, row := range rows {
		_, err = stmt.Exec(
			row.CallID,
			row.EndDate,
			row.SIPStatus,
		)
		logp.Warn("sipstatus - %v", row.SIPStatus)
		if err != nil {
			logp.Err("%v", err)
			continue
		}
	}

	err = stmt.Close()
	if err != nil {
		logp.Err("%v", err)
	}

	err = tx.Commit()
	if err != nil {
		logp.Err("%v", err)
	}

	logp.Debug("sql", "%s\n\n%v\n\n", query, rows)
}

func (p *Postgres) bulkInsert(query string, rows []string) {
	tx, err := p.db.Begin()
	if err != nil || tx == nil {
		logp.Err("%v", err)
		return
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		logp.Err("%v", err)
		err := tx.Rollback()
		if err != nil {
			logp.Err("%v", err)
		}
		return
	}

	for i := 0; i < len(rows); i = i + 5 {
		_, err = stmt.Exec(rows[i], rows[i+1], rows[i+2], rows[i+3], rows[i+4])
		if err != nil {
			logp.Err("%v", err)
			continue
		}
	}

	_, err = stmt.Exec()
	if err != nil {
		logp.Err("%v", err)
	}
	err = stmt.Close()
	if err != nil {
		logp.Err("%v", err)
	}
	err = tx.Commit()
	if err != nil {
		logp.Err("%v", err)
	}

	logp.Debug("sql", "%s\n\n%v\n\n", query, rows)
}

func (p *Postgres) insertRTP(sid, date, pHeader, dHeader string, payload []byte) {
	tx, err := p.db.Begin()
	if err != nil || tx == nil {
		logp.Err("%v", err)
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	insertQuery := `
		insert into hep_proto_7_default (sid, create_date, protocol_header, data_header, raw)
		values ($1, $2, $3, $4, $5)
	`
	_, er := tx.Exec(insertQuery,
		sid,
		date,
		pHeader,
		dHeader,
		payload,
	)
	if er != nil {
		logp.Err("insert error %v", er)
	}

	err = tx.Commit()
	if err != nil {
		logp.Err("commit error %v", err)
		tx.Rollback()
		return
	}
}
