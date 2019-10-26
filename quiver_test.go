package quiver_test

import (
	"github.com/gadelkareem/quiver"
	"testing"
)

func TestNewProxyFactory(t *testing.T) {
	p := quiver.NewProxyFactory(quiver.UseAllProxy, 10, false, true, true, "./testdata", "", "", )
	for i := 0; i < p.TotalCount(); i++ {
		ip, u := p.RandomProxy()
		println(ip, u.String(), p.TotalCount())
	}
}
