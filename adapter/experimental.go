package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/varbin"
)

type ClashServer interface {
	LifecycleService
	ConnectionTracker
	Mode() string
	ModeList() []string
	SetModeUpdateHook(hook *observable.Subscriber[struct{}])
	HistoryStorage() URLTestHistoryStorage
}

type URLTestHistory struct {
	Time        time.Time      `json:"time"`
	Delay       uint16         `json:"delay"`
	IpInfo      *ipinfo.IpInfo `json:"ipinfo"`
	IsFromCache bool           `json:"from_cache"`

	// Throughput evidence, populated only by the bulk (sized-GET) probe.
	//
	// Delay alone cannot distinguish a healthy node from one a censor has
	// frozen: state censors (TSPU in particular) let the TCP handshake and TLS
	// complete normally and only stop forwarding after roughly 16-20 KB. A HEAD
	// request to a /generate_204 endpoint transfers no body at all, so it
	// returns instantly over a path that in reality carries nothing. These
	// fields record what a transfer large enough to cross that threshold
	// actually achieved.
	//
	// CarriedBytes is how many body bytes were really read. Zero means either
	// "never probed" or "probed and carried nothing" -- consumers must tell
	// those apart via ThroughputMeasured, or a fresh start would look like a
	// total outage.
	CarriedBytes int64 `json:"carried_bytes,omitempty"`
	// ThroughputKBps is CarriedBytes over the elapsed transfer time, in KB/s.
	ThroughputKBps uint32 `json:"throughput_kbps,omitempty"`
	// ThroughputTime is when the bulk probe last completed; zero means never.
	ThroughputTime time.Time `json:"throughput_time,omitempty"`
}

// ThroughputMeasured reports whether a bulk probe has ever produced a verdict
// for this outbound. An unmeasured node must not be treated as proven-dead.
func (h *URLTestHistory) ThroughputMeasured() bool {
	return h != nil && !h.ThroughputTime.IsZero()
}

type URLTestHistoryStorage interface {
	SetHook(hook *observable.Subscriber[struct{}])
	LoadURLTestHistory(tag string) *URLTestHistory
	DeleteURLTestHistory(tag string)
	StoreURLTestHistory(tag string, history *URLTestHistory) *URLTestHistory
	AddOnlyIpToHistory(tag string, history *URLTestHistory)
	Close() error
}

type V2RayServer interface {
	LifecycleService
	StatsService() ConnectionTracker
}

type CacheFile interface {
	LifecycleService

	StoreFakeIP() bool
	FakeIPStorage

	StoreRDRC() bool
	RDRCStore

	StoreWARPConfig() bool
	StoreMASQUEConfig() bool

	StoreDNS() bool
	DNSCacheStore

	SetDisableExpire(disableExpire bool)
	SetOptimisticTimeout(timeout time.Duration)

	LoadMode() string
	StoreMode(mode string) error
	LoadSelected(group string) string
	StoreSelected(group string, selected string) error
	LoadGroupExpand(group string) (isExpand bool, loaded bool)
	StoreGroupExpand(group string, expand bool) error
	LoadRuleSet(tag string) *SavedBinary
	SaveRuleSet(tag string, set *SavedBinary) error
	LoadBinary(tag string) *SavedBinary
	SaveBinary(tag string, set *SavedBinary) error
}

type SavedBinary struct {
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(1))
	if err != nil {
		return nil, err
	}
	err = varbin.Write(&buffer, binary.BigEndian, s.Content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	err = varbin.Write(&buffer, binary.BigEndian, s.LastEtag)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	err = varbin.Read(reader, binary.BigEndian, &s.Content)
	if err != nil {
		return err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	err = varbin.Read(reader, binary.BigEndian, &s.LastEtag)
	if err != nil {
		return err
	}
	return nil
}

type OutboundGroup interface {
	Outbound
	Now() string
	All() []string
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

func OutboundTag(detour Outbound) string {
	if group, isGroup := detour.(OutboundGroup); isGroup {
		return group.Now()
	}
	return detour.Tag()
}
