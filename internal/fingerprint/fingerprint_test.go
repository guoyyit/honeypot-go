package fingerprint

import (
	"testing"
)

func TestMatchHits(t *testing.T) {
	m := NewMatcher(DefaultRules())

	cases := []struct {
		kind   string
		chunks [][]byte
		want   string
	}{
		{"http", [][]byte{[]byte("GET / HTTP/1.1\r\nUser-Agent: nmap scripting\r\n\r\n")}, "nmap-http"},
		{"http", [][]byte{[]byte("GET /.env HTTP/1.1\r\nX: 1\r\n"), []byte("more")}, "http-path-scan-config"},
		{"http", [][]byte{[]byte("GET / HTTP/1.1\r\n"), []byte("User-Agent: sqlmap/1.0\r\n")}, "sqlmap"},
		{"ssh", [][]byte{[]byte("SSH-2.0-Nmap_NSE\r\n")}, "nmap-ssh"},
		{"ftp", [][]byte{[]byte("USER anonymous\r\n")}, "ftp-anon-probe"},
		{"ftp", [][]byte{[]byte("USER bob\r\n"), []byte("PASS secret\r\n")}, "hydra-ftp-bruteforce"},
		{"tcp", [][]byte{[]byte("\x16\x03\x01\x00")}, "tls-clienthello"},
	}
	for _, tc := range cases {
		name, ok := m.Match(tc.kind, tc.chunks)
		if !ok {
			t.Fatalf("kind=%s expected hit %q, got miss", tc.kind, tc.want)
		}
		if name != tc.want {
			t.Fatalf("kind=%s want %q got %q", tc.kind, tc.want, name)
		}
	}
}

func TestMatchMiss(t *testing.T) {
	m := NewMatcher(DefaultRules())
	if name, ok := m.Match("http", [][]byte{[]byte("GET / HTTP/1.1\r\nUser-Agent: my-custom-client\r\n")}); ok {
		t.Fatalf("unexpected hit: %s", name)
	} else if name != Miss {
		t.Fatalf("want miss marker %q, got %q", Miss, name)
	}
	if name, ok := m.Match("http", nil); ok || name != Miss {
		t.Fatalf("empty chunks must be miss, got %q ok=%v", name, ok)
	}
}

func TestMatchOrderedPatterns(t *testing.T) {
	m := NewMatcher([]Rule{{Name: "seq", Kind: "tcp", Patterns: []string{"a", "b"}}})
	if _, ok := m.Match("tcp", [][]byte{[]byte("xxbxxaxx")}); ok {
		t.Fatal("patterns must match in order")
	}
	if name, ok := m.Match("tcp", [][]byte{[]byte("a"), []byte("xb")}); !ok || name != "seq" {
		t.Fatalf("ordered multi-chunk match failed: %q %v", name, ok)
	}
}

func TestMatchKindScoped(t *testing.T) {
	m := NewMatcher(DefaultRules())
	// nmap HTTP UA 不应命中 ssh 规则
	if _, ok := m.Match("ssh", [][]byte{[]byte("User-Agent: nmap\r\n")}); ok {
		t.Fatal("http rule must not match ssh kind")
	}
}
