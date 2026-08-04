package libv2ray

import (
	"net"
	"testing"
	"time"
)

type fakeSupportSet struct{}

func (fakeSupportSet) Protect(int) bool {
	return true
}

func TestResolvedCurrentIP(t *testing.T) {
	resolvedAddress := &resolved{
		domain: "example.invalid",
		IPs: []net.IP{
			net.ParseIP("192.0.2.1"),
			net.ParseIP("2001:db8::1"),
		},
	}

	if got := resolvedAddress.currentIP(); !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("unexpected initial IP: %v", got)
	}
}

func TestResolvedNextIPCyclesDeterministically(t *testing.T) {
	resolvedAddress := &resolved{
		domain: "example.invalid",
		IPs: []net.IP{
			net.ParseIP("192.0.2.1"),
			net.ParseIP("192.0.2.2"),
		},
		lastSwitched: time.Unix(0, 0),
	}

	resolvedAddress.NextIP()
	if got := resolvedAddress.currentIP(); !got.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("unexpected IP after first switch: %v", got)
	}

	resolvedAddress.lastSwitched = time.Unix(0, 0)
	resolvedAddress.NextIP()
	if got := resolvedAddress.currentIP(); !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("unexpected IP after wraparound: %v", got)
	}
}

func TestResolvedNextIPKeepsSingleAddress(t *testing.T) {
	resolvedAddress := &resolved{
		IPs:          []net.IP{net.ParseIP("192.0.2.1")},
		lastSwitched: time.Unix(0, 0),
	}

	resolvedAddress.NextIP()
	if got := resolvedAddress.currentIP(); !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("single IP changed: %v", got)
	}
}

func TestProtectedDialerResolveChannelLifecycle(t *testing.T) {
	dialer := NewPreotectedDialer(fakeSupportSet{})
	if dialer.IsVServerReady() {
		t.Fatal("new dialer unexpectedly has a prepared server")
	}

	dialer.PrepareResolveChan()
	if dialer.ResolveChan() == nil {
		t.Fatal("resolve channel was not initialized")
	}
}
