package urltest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHook   *observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) SetHook(hook *observable.Subscriber[struct{}]) {
	s.updateHook = hook
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Delay: 65535,
		Time:  time.Now(),
	})
	// s.access.Lock()
	// // delete(s.delayHistory, tag)
	// s.access.Unlock()
	// s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) *adapter.URLTestHistory {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.Delay = history.Delay
		old.Time = history.Time
		if history.IpInfo != nil {
			old.IpInfo = history.IpInfo
		}
	} else {
		s.delayHistory[tag] = history
	}
	history = s.delayHistory[tag]
	s.access.Unlock()
	s.notifyUpdated()
	return history
}

func (s *HistoryStorage) AddOnlyIpToHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	if old, ok := s.delayHistory[tag]; ok && history != nil {
		old.IpInfo = history.IpInfo
	} else {
		s.delayHistory[tag] = history
	}
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	updateHook := s.updateHook
	if updateHook != nil {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHook = nil
	return nil
}

// URLTest reports a node as unreachable only after it has genuinely had a
// chance to answer.
//
// WHY THIS RETRIES
// A single 15 s attempt marks two perfectly working transports dead:
//   - QUIC-based ones (TUIC, Hysteria2, juicity) frequently lose the first
//     handshake datagram; the retransmit succeeds, but the probe has already
//     given up.
//   - An I2P lane needs to build a circuit through several hops before it can
//     carry anything, which routinely takes longer than one attempt.
//
// Both then show as a red cross in the UI and are excluded from the auto group
// even though they carry traffic fine — which is exactly backwards, since those
// are the lanes that survive when the direct ones get blocked.
//
// So: up to three attempts with a short pause. The cost is bounded (a dead node
// still fails within the same overall budget) and the benefit is that "dead"
// starts meaning dead.
func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	const attempts = 3
	for i := 0; i < attempts; i++ {
		t, err = urlTestOnce(ctx, link, detour)
		if err == nil {
			return
		}
		// Give up early if the caller is gone; retrying would be pointless.
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	return
}

func urlTestOnce(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if detour == nil {
		err = fmt.Errorf("urltest dialer is nil")
		return
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// 15 s (C.TCPTimeout) is fine for a direct hop but far too short for a
		// lane that has to build a multi-hop circuit first — I2P routinely needs
		// longer, and would otherwise be reported dead while working.
		Timeout: 40 * time.Second,
	}
	defer client.CloseIdleConnections()
	select {
	case <-ctx.Done():
		return
	default:
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()

	t = uint16(time.Since(start) / time.Millisecond)

	if IsUnifiedDelayFromContext(ctx) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		second := time.Now()
		resp, err = client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		t = uint16(time.Since(second) / time.Millisecond) //to avid timeout in the second call
	}
	return
}
