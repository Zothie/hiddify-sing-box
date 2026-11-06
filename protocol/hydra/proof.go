package hydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// proofTarget describes a trusted HTTPS origin implementing the nonce proof.
// The origin returns X-Hydra-Nonce and SHA256(nonce || uint32_be(block)) blocks.
type proofTarget struct {
	URL   string
	Bytes int
	TLS   *tls.Config
}

func verifyTunnelProof(ctx context.Context, tunnel *Tunnel, target proofTarget) error {
	if target.Bytes < 1024 || target.Bytes > 1024*1024 {
		return fmt.Errorf("hydra proof: size outside 1 KiB..1 MiB")
	}
	u, err := url.Parse(target.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("hydra proof: invalid HTTPS origin")
	}
	if target.TLS != nil && (target.TLS.InsecureSkipVerify || target.TLS.ServerName != "") {
		return fmt.Errorf("hydra proof: TLS identity overrides are forbidden")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	nonceText := hex.EncodeToString(nonce[:])
	query := u.Query()
	query.Set("nonce", nonceText)
	query.Set("bytes", strconv.Itoa(target.Bytes))
	u.RawQuery = query.Encode()

	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 8192,
		TLSClientConfig:        target.TLS,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return nil, err
			}
			return tunnel.openSession(dialCtx, host, uint16(port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("hydra proof: request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Hydra-Nonce") != nonceText || response.ContentLength != int64(target.Bytes) || response.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("hydra proof: unexpected response metadata")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(target.Bytes)+1))
	if err != nil {
		return fmt.Errorf("hydra proof: incomplete body: %w", err)
	}
	if len(body) != target.Bytes {
		return fmt.Errorf("hydra proof: unexpected byte count")
	}
	for offset, block := 0, uint32(0); offset < len(body); block++ {
		input := binary.BigEndian.AppendUint32([]byte(nonceText), block)
		digest := sha256.Sum256(input)
		n := min(sha256.Size, len(body)-offset)
		if !bytes.Equal(body[offset:offset+n], digest[:n]) {
			return fmt.Errorf("hydra proof: byte integrity mismatch")
		}
		offset += n
	}
	return nil
}
