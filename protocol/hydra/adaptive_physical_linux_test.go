//go:build linux && !android

package hydra

import (
	"testing"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func TestAdaptivePhysicalDialerRejectsDNSHostnames(t *testing.T) {
	_, err := newAdaptivePhysicalDialer(t.Context(), &option.HydraAdaptiveOptions{
		PhysicalDNSServers: []string{"resolver.example:53"},
	}, option.HydraAdaptiveCandidateOptions{})
	if err == nil || !strings.Contains(err.Error(), "DNS endpoint") {
		t.Fatalf("nonliteral DNS was not rejected before interface lookup: %v", err)
	}
}

func TestAdaptivePhysicalDialerRejectsUnsafePaths(t *testing.T) {
	for _, iface := range []string{"", "lo", "hydra-nonexistent-iface"} {
		_, err := newAdaptivePhysicalDialer(t.Context(), &option.HydraAdaptiveOptions{PhysicalInterface: iface}, option.HydraAdaptiveCandidateOptions{})
		if err == nil {
			t.Fatalf("unsafe physical interface %q accepted", iface)
		}
	}
}
