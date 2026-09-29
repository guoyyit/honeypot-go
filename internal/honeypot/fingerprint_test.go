package honeypot

import (
	"testing"

	"github.com/guoyyit/honeypot-go/internal/config"
	"github.com/guoyyit/honeypot-go/internal/fingerprint"
	"github.com/guoyyit/honeypot-go/internal/session"
)

func TestFingerprintMatching(t *testing.T) {
	rules := []config.FingerprintRule{
		{Name: "nmap", Protocol: config.ProtocolSSH, Any: true, Patterns: []string{"SSH-2.0-Nmap"}},
		{Name: "hydra", Protocol: config.ProtocolFTP, Any: false, Patterns: []string{"USER ", "PASS "}},
		{Name: "curl", Protocol: config.ProtocolHTTP, Any: true, Patterns: []string{"User-Agent: curl/"}},
	}
	m := fingerprint.NewMatcher(rules)

	cases := []struct {
		name       string
		proto      config.Protocol
		transcript []string
		wantName   string
		wantMatch  bool
	}{
		{"nmap ssh banner", config.ProtocolSSH, []string{"SSH-2.0-Nmap_NES"}, "nmap", true},
		{"hydra ordered", config.ProtocolFTP, []string{"USER bob\r\n", "PASS pw\r\n"}, "hydra", true},
		{"hydra wrong order", config.ProtocolFTP, []string{"PASS pw\r\n", "USER bob\r\n"}, session.FingerprintMiss, false},
		{"curl ua", config.ProtocolHTTP, []string{"GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\n"}, "curl", true},
		{"protocol isolation", config.ProtocolHTTP, []string{"SSH-2.0-Nmap"}, session.FingerprintMiss, false},
		{"unknown traffic", config.ProtocolTCP, []string{"hello\r\n"}, session.FingerprintMiss, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := m.Match(tc.proto, tc.transcript)
			if res.Name != tc.wantName || res.Matched != tc.wantMatch {
				t.Fatalf("got (%q,%v), want (%q,%v)", res.Name, res.Matched, tc.wantName, tc.wantMatch)
			}
			if !tc.wantMatch && res.Name != session.FingerprintMiss {
				t.Fatalf("miss must be marked %q, got %q", session.FingerprintMiss, res.Name)
			}
		})
	}
}

// TestFingerprintRecordedInSession 验证识别结果写入持久化会话记录。
func TestFingerprintRecordedInSession(t *testing.T) {
	hp, _ := startHoneypot(t)
	addr := mustAddr(t, hp, "svc-ssh")
	c := dial(t, addr)
	defer c.Close()
	readAll(t, c, 1)
	ftpSend(t, c, "SSH-2.0-Nmap_NES\r\n")
	readAll(t, c, 1)

	waitSessions(t, hp, 1)
	sess := onlySession(t, hp)
	if sess.Fingerprint != "nmap" {
		t.Fatalf("fingerprint = %q, want nmap", sess.Fingerprint)
	}
}
