//go:build !linux || android

package hydra

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func newAdaptivePhysicalDialer(context.Context, *option.HydraAdaptiveOptions, option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
	return nil, fmt.Errorf("%w: adaptive platform network binding not implemented", dialer.ErrPhysicalUnavailable)
}
