package server

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		ok     bool
		scheme string
		host   string
		port   int
	}{
		// URL 分支
		{"url https with port", "check https://Example.COM:8443/x now", true, "https", "example.com", 8443},
		{"url http default port", "see http://10.0.0.5/admin", true, "http", "10.0.0.5", 80},
		{"url ipv6", "probe http://[::1]:8080/x", true, "http", "::1", 8080},
		{"url port over 65535 falls back", "http://1.2.3.4:99999/", true, "http", "1.2.3.4", 80},

		// 合法 IP[:port]
		{"ip with port", "target 192.168.1.10:8080 please", true, "http", "192.168.1.10", 8080},
		{"ip bare", "scan 10.0.0.1 today", true, "http", "10.0.0.1", 80},
		{"ip https port", "1.2.3.4:443", true, "https", "1.2.3.4", 443},
		{"ip embedded second candidate", "bad 1.2.3.4.5 and 5.6.7.8 ok", true, "http", "5.6.7.8", 80},

		// 非法四段组必须整体拒绝（issue #9）
		{"quad all 999", "audit 999.999.999.999 now", false, "", "", 0},
		{"quad 300", "300.1.2.3", false, "", "", 0},
		{"quad trailing 256", "build 1.2.3.256", false, "", "", 0},

		// 嵌在更长点分/数字串里的部分匹配必须拒绝（issue #9）
		{"five octets", "upgraded to 1.2.3.4.5", false, "", "", 0},
		{"long trailing digits", "version 1.2.3.4444", false, "", "", 0},

		// 端口范围（issue #9）：越界端口回退默认端口
		{"port 99999 falls back", "1.2.3.4:99999", true, "http", "1.2.3.4", 80},
		{"port 0 falls back", "1.2.3.4:0", true, "http", "1.2.3.4", 80},

		// 域名分支
		{"domain bare", "www.example.com", true, "https", "www.example.com", 443},
		{"domain with port", "example.com:8080", true, "http", "example.com", 8080},
		{"domain port over 65535 falls back", "example.com:70000", true, "https", "example.com", 443},

		// 无目标
		{"plain text", "just a routine task about payment reconciliation", false, "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme, host, port, ok := parseTarget(tc.in)
			if ok != tc.ok || scheme != tc.scheme || host != tc.host || port != tc.port {
				t.Errorf("parseTarget(%q) = (%q, %q, %d, %v), want (%q, %q, %d, %v)",
					tc.in, scheme, host, port, ok, tc.scheme, tc.host, tc.port, tc.ok)
			}
		})
	}
}
