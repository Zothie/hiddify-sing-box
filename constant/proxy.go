package constant

const (
<<<<<<< HEAD
	TypeTun           = "tun"
	TypeRedirect      = "redirect"
	TypeTProxy        = "tproxy"
	TypeDirect        = "direct"
	TypeBlock         = "block"
	TypeDNS           = "dns"
	TypeSOCKS         = "socks"
	TypeHTTP          = "http"
	TypeMixed         = "mixed"
	TypeShadowsocks   = "shadowsocks"
	TypeVMess         = "vmess"
	TypeTrojan        = "trojan"
	TypeNaive         = "naive"
	TypeWireGuard     = "wireguard"
	TypeHysteria      = "hysteria"
	TypeTor           = "tor"
	TypeSSH           = "ssh"
	TypeShadowTLS     = "shadowtls"
	TypeShadowsocksR  = "shadowsocksr"
	TypeVLESS         = "vless"
	TypeTUIC          = "tuic"
	TypeHysteria2     = "hysteria2"
	TypeCustom        = "custom"
	TypeXray          = "xray"
	TypeInvalidConfig = "invalid"
=======
	TypeTun                = "tun"
	TypeRedirect           = "redirect"
	TypeTProxy             = "tproxy"
	TypeDirect             = "direct"
	TypeBlock              = "block"
	TypeDNS                = "dns"
	TypeSOCKS              = "socks"
	TypeHTTP               = "http"
	TypeMixed              = "mixed"
	TypeShadowsocks        = "shadowsocks"
	TypeVMess              = "vmess"
	TypeTrojan             = "trojan"
	TypeNaive              = "naive"
	TypeWireGuard          = "wireguard"
	TypeWARP               = "warp"
	TypeHysteria           = "hysteria"
	TypeTor                = "tor"
	TypeSSH                = "ssh"
	TypeShadowTLS          = "shadowtls"
	TypeMieru              = "mieru"
	TypeAnyTLS             = "anytls"
	TypeShadowsocksR       = "shadowsocksr"
	TypeVLESS              = "vless"
	TypeTUIC               = "tuic"
	TypeHysteria2          = "hysteria2"
	TypePsiphon            = "psiphon"
	TypeTunnelClient       = "tunnel_client"
	TypeTunnelServer       = "tunnel_server"
	TypeTailscale          = "tailscale"
	TypeCloudflared        = "cloudflared"
	TypeDERP               = "derp"
	TypeResolved           = "resolved"
	TypeSSMAPI             = "ssm-api"
	TypeCCM                = "ccm"
	TypeOCM                = "ocm"
	TypeOOMKiller          = "oom-killer"
	TypeACME               = "acme"
	TypeCloudflareOriginCA = "cloudflare-origin-ca"

	TypeHInvalidConfig = "hinvalid"       //H
	TypeXray           = "xray"           //H
	TypeCustom         = "custom"         //H
	TypeAwg            = "awg"            //H
	TypeBalancer       = "balancer"       //H
	TypeDNSTT          = "dnstt"          //H
	TypeMasterDNS      = "masterdns"      //H
	TypeGooseRelay     = "gooserelay"     //H
	TypeHydra          = "hydra"          //H
	TypeSmartDNSPool   = "smart_dns_pool" //H — local recursive-resolver pool with AIMD throttling + recovery probing (github.com/hiddify/hmrd_multi_resolver_dns)
>>>>>>> 6ba438df (Add hydra outbound protocol (own VPN core, WS/TLS + AEAD multiplexed sessions))
)

const (
	TypeSelector = "selector"
	TypeURLTest  = "urltest"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeDirect:
		return "Direct"
	case TypeBlock:
		return "Block"
	case TypeDNS:
		return "DNS"
	case TypeSOCKS:
		return "SOCKS"
	case TypeHTTP:
		return "HTTP"
	case TypeShadowsocks:
		return "Shadowsocks"
	case TypeVMess:
		return "VMess"
	case TypeTrojan:
		return "Trojan"
	case TypeNaive:
		return "Naive"
	case TypeWireGuard:
		return "WireGuard"
	case TypeHysteria:
		return "Hysteria"
	case TypeTor:
		return "Tor"
	case TypeSSH:
		return "SSH"
	case TypeShadowTLS:
		return "ShadowTLS"
	case TypeShadowsocksR:
		return "ShadowsocksR"
	case TypeVLESS:
		return "VLESS"
	case TypeTUIC:
		return "TUIC"
	case TypeHysteria2:
		return "Hysteria2"
	case TypeSelector:
		return "Selector"
	case TypeURLTest:
		return "URLTest"
<<<<<<< HEAD
=======
	case TypeHInvalidConfig:
		return "Invalid"
	case TypeXray:
		return "xray"
	case TypeCustom:
		return "custom"
	case TypeTunnelClient:
		return "Tunnel Client"
	case TypeTunnelServer:
		return "Tunnel Server"
	case TypeAwg:
		return "Awg"
	case TypeBalancer:
		return "Balancer"
	case TypeDNSTT:
		return "DNSTT"
	case TypeMasterDNS:
		return "MasterDNS"
	case TypeGooseRelay:
		return "GooseRelay"
	case TypeHydra:
		return "Hydra"
>>>>>>> 6ba438df (Add hydra outbound protocol (own VPN core, WS/TLS + AEAD multiplexed sessions))
	default:
		return "Unknown"
	}
}
