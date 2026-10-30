package main

import "testing"

func TestLoopbackOnly(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isLoopback(host) { t.Errorf("%s rejected", host) }
	}
	for _, host := range []string{"", "0.0.0.0", "::", "192.168.1.1", "example.com"} {
		if isLoopback(host) { t.Errorf("%s accepted", host) }
	}
}
