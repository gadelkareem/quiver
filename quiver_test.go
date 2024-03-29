package quiver_test

import (
	"fmt"
	"os"
	"testing"

	pw "github.com/gadelkareem/proxy.webshare.io"
	"github.com/gadelkareem/quiver"
)

func TestNewProxyFactory(t *testing.T) {
	u := os.Getenv("PW_URL")
	if u == "" {
		panic("Please provide a proxy.webshare.io download list URL")
	}
	pwProxy, err := pw.NewClient(u, nil)
	if err != nil {
		t.Error(err)
		return
	}
	p := quiver.NewProxyFactory(quiver.UseAllProxy, 10, false, true, true, "./testdata", "", "", pwProxy)
	tl := p.TotalCount()
	for i := 0; i < tl; i++ {
		ip, u := p.RandomProxy()
		println(ip, u.String())
	}
	fmt.Printf("Got %d proxies \n", tl)
	if tl < 260 {
		t.Error("Invalid number of proxies")
	}
}
