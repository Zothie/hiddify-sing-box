package hydra

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func proofTestBody(nonce string, size int) []byte {
	body := make([]byte, 0, size+sha256.Size)
	for i := uint32(0); len(body) < size; i++ {
		input := binary.BigEndian.AppendUint32([]byte(nonce), i)
		sum := sha256.Sum256(input)
		body = append(body, sum[:]...)
	}
	return body[:size]
}

func TestCandidateProof(t *testing.T) {
	serverAddr, pubkey, _ := startRustServer(t)
	for _, mode := range []string{"valid", "corrupt", "truncated", "wrong-nonce", "redirect", "stall", "untrusted", "insecure-override", "servername-override"} {
		t.Run(mode, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("proof used %s instead of GET", r.Method)
				}
				nonce := r.URL.Query().Get("nonce")
				decoded, err := hex.DecodeString(nonce)
				if err != nil || len(decoded) != 32 {
					t.Errorf("invalid proof nonce: %q", nonce)
				}
				if mode == "redirect" {
					w.Header().Set("Location", "/unexpected")
					w.WriteHeader(http.StatusFound)
					return
				}
				w.Header().Set("X-Hydra-Nonce", nonce)
				if mode == "wrong-nonce" {
					w.Header().Set("X-Hydra-Nonce", "old-request")
				}
				body := proofTestBody(nonce, 8192)
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				if mode == "stall" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				if mode == "corrupt" {
					body[len(body)/2] ^= 1
				}
				if mode == "truncated" {
					body = body[:len(body)/2]
				}
				_, _ = w.Write(body)
			}))
			defer origin.Close()
			roots := x509.NewCertPool()
			if mode != "untrusted" {
				roots.AddCert(origin.Certificate())
			}
			tlsConfig := &tls.Config{RootCAs: roots}
			if mode == "insecure-override" {
				tlsConfig.InsecureSkipVerify = true
			}
			if mode == "servername-override" {
				tlsConfig.ServerName = "different-origin.invalid"
			}
			tunnel := connectTestTunnel(t, serverAddr, pubkey)
			defer tunnel.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			start := time.Now()
			err := verifyTunnelProof(ctx, tunnel, proofTarget{
				URL: origin.URL, Bytes: 8192, TLS: tlsConfig,
			})
			if mode == "valid" && err != nil {
				t.Fatalf("valid useful proof rejected: %v", err)
			}
			if mode != "valid" && err == nil {
				t.Fatalf("false success for %s response", mode)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("proof exceeded its total deadline")
			}
		})
	}
}
