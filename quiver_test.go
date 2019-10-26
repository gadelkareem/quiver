package quiver_test

import (
	"github.com/gadelkareem/quiver"
	"testing"
)

func TestNewProxyFactory(t *testing.T) {
	p := quiver.NewProxyFactory(quiver.UseAllProxy, 10, false, true, true, "./testdata", "", "", )
	tl := p.TotalCount()
	for i := 0; i < tl; i++ {
		ip, u := p.RandomProxy()
		println(ip, u.String())
	}
}
