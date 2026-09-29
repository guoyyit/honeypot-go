package honeypot

import (
	"bufio"
	"strings"
	"testing"
)

// TestMultiServiceCoexistence 覆盖 HTTP/SSH/FTP/TCP 同时运行且互不影响。
func TestMultiServiceCoexistence(t *testing.T) {
	hp, _ := startHoneypot(t)

	httpAddr := mustAddr(t, hp, "svc-http")
	sshAddr := mustAddr(t, hp, "svc-ssh")
	ftpAddr := mustAddr(t, hp, "svc-ftp")
	tcpAddr := mustAddr(t, hp, "svc-tcp")

	// HTTP
	resp := httpGet(t, httpAddr, "/", "")
	if !strings.Contains(resp, "200") || !strings.Contains(resp, "ok-body") {
		t.Fatalf("unexpected http response: %q", resp)
	}

	// SSH：读取横幅
	sshConn := dial(t, sshAddr)
	defer sshConn.Close()
	sshLine, err := bufio.NewReader(sshConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read ssh banner: %v", err)
	}
	if !strings.HasPrefix(sshLine, "SSH-2.0-OpenSSH") {
		t.Fatalf("unexpected ssh banner: %q", sshLine)
	}
	ftpSend(t, sshConn, "SSH-2.0-Go\r\n")

	// FTP：读取横幅并登录
	ftpConn := dial(t, ftpAddr)
	defer ftpConn.Close()
	ftpR := bufio.NewReader(ftpConn)
	banner, _ := ftpR.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		t.Fatalf("unexpected ftp banner: %q", banner)
	}
	ftpSend(t, ftpConn, "USER root\r\n")
	if line, _ := ftpR.ReadString('\n'); !strings.HasPrefix(line, "331") {
		t.Fatalf("expected 331, got %q", line)
	}
	ftpSend(t, ftpConn, "PASS secret\r\n")
	if line, _ := ftpR.ReadString('\n'); !strings.HasPrefix(line, "230") {
		t.Fatalf("expected 230, got %q", line)
	}

	// TCP：横幅 + 交互
	tcpConn := dial(t, tcpAddr)
	defer tcpConn.Close()
	tcpR := bufio.NewReader(tcpConn)
	tcpBanner, _ := tcpR.ReadString('\n')
	if !strings.Contains(tcpBanner, "WELCOME") {
		t.Fatalf("unexpected tcp banner: %q", tcpBanner)
	}
	ftpSend(t, tcpConn, "PING\n")
	if line, _ := tcpR.ReadString('\n'); !strings.Contains(line, "ack") {
		t.Fatalf("unexpected tcp reply: %q", line)
	}

	waitSessions(t, hp, 4)
	sessions, err := hp.Sessions()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	got := map[string]bool{}
	for _, s := range sessions {
		got[s.Protocol] = true
		if len(s.Events) < 2 {
			t.Fatalf("session %s(%s) has <2 events", s.ID, s.Protocol)
		}
	}
	for _, proto := range []string{"http", "ssh", "ftp", "tcp"} {
		if !got[proto] {
			t.Fatalf("missing session for protocol %s (got=%v)", proto, got)
		}
	}

	// 列表中四个服务都处于 active，证明彼此独立运行。
	for _, st := range hp.Manager().List() {
		if st.State.String() != "active" {
			t.Fatalf("service %s state = %s, want active", st.Name, st.State)
		}
	}
}
