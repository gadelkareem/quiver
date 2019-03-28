package quiver

import (
	"bufio"
	"github.com/astaxie/beego/logs"
	"github.com/gadelkareem/go-helpers"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	UseNoProxy         = 0
	UseIPv4Proxy       = 1
	UseIPv6Proxy       = 2
	UseMappedIPv6Proxy = 3
	UseAllProxy        = 10
	MaxProxies         = 10000
)

type ProxyFactory interface {
	RandomProxy() (ip string, u *url.URL)
	TotalCount() int
}

type proxies struct {
	sync.Mutex
	disableRotation, disableTest, disableAuth bool
	proxiesPath, token, ipToken               string
	proxyType, maxProxies, totalCount         int
	ipCache                                   map[string]bool
	mappedIpv6s, ipv4s, ipv6s                 map[string]*url.URL
}

func NewProxyFactory(proxyType int, maxProxies int, disableRotation, disableTest, disableAuth bool, proxiesPath, token, ipToken string) ProxyFactory {

	p := &proxies{}

	p.ipv6s = make(map[string]*url.URL)
	p.mappedIpv6s = make(map[string]*url.URL)
	p.ipv4s = make(map[string]*url.URL)
	p.ipCache = make(map[string]bool)

	if maxProxies <= 0 {
		maxProxies = MaxProxies
	}

	p.maxProxies = maxProxies
	p.disableRotation = disableRotation
	p.disableTest = disableTest
	p.proxyType = proxyType
	p.proxiesPath = proxiesPath
	p.disableAuth = disableAuth
	p.token = token
	p.ipToken = ipToken

	p.load()

	logs.Alert("Found %d total proxies", p.totalCount)

	return p
}

func (p *proxies) TotalCount() int {
	return p.totalCount
}

func (p *proxies) load() {
	switch p.proxyType {
	case UseAllProxy:
		p.loadIpv6MappedProxy()
		p.loadIpv6Proxy()
		p.loadIpv4Proxy()
	case UseIPv4Proxy:
		p.loadIpv4Proxy()
	case UseMappedIPv6Proxy:
		p.loadIpv6MappedProxy()
		p.loadIpv6Proxy()
	case UseIPv6Proxy:
		p.loadIpv6Proxy()
	case UseNoProxy:
	default:
		return
	}
	p.disableTest = true
}

func (p *proxies) loadIpv6Proxy() {

	var ip net.IP
	lines := p.readProxiesFile("ipv6")
	newService := false
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			newService = true
			continue
		}
		proxyInfo := strings.Split(line, "|")
		if len(proxyInfo) != 2 {
			panic("Bad proxy line " + line)
		}
		port := proxyInfo[1]
		ip = net.ParseIP(proxyInfo[0])
		if ip == nil {
			panic("Wrong IP: " + line)
		}
		rawIp := ip.String()
		if p.isCached(rawIp) {
			continue
		}
		logs.Alert("Found IP %s", rawIp)

		authString := p.tokenString(rawIp)

		proxyString := "http://" + authString + "[" + rawIp + "]:" + port
		proxyUrl, err := url.Parse(proxyString)
		if err != nil {
			panic("Failed to parse proxies URL:" + proxyString)
		}
		p.ipv6s[rawIp] = proxyUrl
		p.ipCache[rawIp] = true
		if !p.disableTest && newService {
			p.testProxy(proxyUrl, ip)
			newService = false
		}

	}
	p.totalCount += len(p.ipv6s)

	logs.Alert("Found %d IPv6 proxies.", len(p.ipv6s))
}

func (p *proxies) loadIpv6MappedProxy() {

	lines := p.readProxiesFile("ipv6-mapped")
	totalSubnets := len(lines)
	if totalSubnets == 0 {
		return
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		proxyInfo := strings.Split(line, "|")
		if len(proxyInfo) != 3 {
			panic("Bad proxy line " + line)
		}
		port := proxyInfo[2]
		serverIp, subnet := proxyInfo[0], proxyInfo[1]
		isServerIpV6 := strings.Contains(serverIp, ":")
		if !strings.Contains(subnet, "/") {
			panic("Error! not a subnet " + line)
		}
		OriginalIp, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			panic("Error! failed to parse IPv6 CIDR" + err.Error())
		}
		var ip net.IP
		for i := 0; i < p.maxProxies; i++ {
			ip = p.generateRandomIPv6(OriginalIp, ipNet)
			rawIp := ip.String()
			authString := p.tokenString(rawIp)
			proxyString := "http://" + authString
			if isServerIpV6 {
				proxyString += "[" + serverIp + "]"
			} else {
				proxyString += serverIp
			}
			proxyString += ":" + port

			proxyUrl, err := url.Parse(proxyString)
			if err != nil {
				panic("Error! fails to parse proxies URL:" + proxyString)
			}
			if p.isCached(rawIp) {
				i--
				continue
			}
			p.mappedIpv6s[rawIp] = proxyUrl
			p.ipCache[rawIp] = true
			if !p.disableTest && i == 0 {
				p.testProxy(proxyUrl, ip)
			}
		}

	}
	p.totalCount += len(p.mappedIpv6s)
	logs.Alert("- Generated %d IPv6 mapped proxies.", len(p.mappedIpv6s))
}

func (p *proxies) testProxy(proxyUrl *url.URL, ip net.IP) {

	transport := &http.Transport{Proxy: http.ProxyURL(proxyUrl), ProxyConnectHeader: http.Header{"Request-IP": []string{ip.String()}}}
	client := &http.Client{Transport: transport}
	client.Timeout = 60 * time.Second

	request, err := http.NewRequest("GET", "https://api.ipify.org/", nil)
	if err != nil {
		panic("Error! proxy failed " + proxyUrl.String())
	}

	response, err := client.Do(request)
	if err != nil {
		panic("proxies failed " + proxyUrl.String() + " Error:" + err.Error())
	}
	defer response.Body.Close()
	bytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic("proxies failed " + proxyUrl.String() + " Error:" + err.Error())
	}
	if response.StatusCode != 200 {
		panic("proxies failed " + proxyUrl.String() + " Status Code:" + string(response.StatusCode))
	}
	body := string(bytes)
	if !strings.Contains(body, ip.String()) {
		panic("proxies failed " + proxyUrl.String() + " Wrong IP address reported \n" + body)
	}

	logs.Alert("proxies test passed %s", proxyUrl)
}

func (p *proxies) generateRandomIPv6(OriginalIp net.IP, ipNet *net.IPNet) net.IP {
	var ip net.IP
	ip = make(net.IP, net.IPv6len)
	copy(ip, OriginalIp)
	for i := 0; i < net.IPv6len; i++ {
		if ipNet.Mask[i] == 0 {
			ip[i] = byte(h.RandomNumber(0, 256))
		}
	}
	return ip
}

func (p *proxies) loadIpv4Proxy() {

	lines := p.readProxiesFile("ipv4")
	newService := true
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			newService = true
			continue
		}
		if p.isCached(line) {
			continue
		}
		lineSplit := strings.Split(line, ":")
		ip := net.ParseIP(lineSplit[0])
		if ip == nil {
			panic("Wrong IP line: " + lineSplit[1])
		}
		rawIp := ip.String()
		proxyString := "http://" + line
		proxyUrl, err := url.Parse(proxyString)
		if err != nil {
			panic("Fails to parse proxies URL:" + proxyString)
		}
		p.ipv4s[rawIp] = proxyUrl
		p.ipCache[rawIp] = true
		if !p.disableTest && newService {
			p.testProxy(proxyUrl, ip)
			newService = false
		}
	}
	p.totalCount += len(p.ipv4s)

	logs.Alert("Found %d IPv4 proxies.", len(p.ipv4s))
}

func (p *proxies) RandomProxy() (ip string, u *url.URL) {
	p.Lock()
	defer p.Unlock()

	//tshk-tshk
	if !p.disableRotation && p.totalCount < 1 {
		if p.proxyType >= UseMappedIPv6Proxy {
			p.loadIpv6MappedProxy()
		} else if p.proxyType == UseIPv4Proxy {
			p.ipCache = make(map[string]bool)
			p.loadIpv4Proxy()
		}
	}

	if p.totalCount < 1 {
		return
	}

	r := h.RandomNumber(0, 100)
	var proxies map[string]*url.URL
	if r > 90 && len(p.ipv4s) > 0 {
		proxies = p.ipv4s
	} else if r > 70 && len(p.ipv6s) > 0 {
		proxies = p.ipv6s
	} else if r > 0 && len(p.mappedIpv6s) > 0 {
		proxies = p.mappedIpv6s
	}

	if len(proxies) == 0 {
		if len(p.mappedIpv6s) > 0 {
			proxies = p.mappedIpv6s
		} else if len(p.ipv6s) > 0 {
			proxies = p.ipv6s
		} else if len(p.ipv4s) > 0 {
			proxies = p.ipv4s
		}
	}

	ip, u = p.randomMapKeyValue(proxies)

	if !p.disableRotation {
		delete(proxies, ip)
		p.totalCount--
	}

	return
}

func (p *proxies) getToken(proxyIp string) string {
	if proxyIp == "" {
		proxyIp = p.ipToken
	}
	s := proxyIp + p.token

	return h.Md5(s)
}

func (p *proxies) tokenString(proxyIp string) string {
	if p.disableAuth {
		return ""
	}
	auth := p.getToken(proxyIp)
	return auth[:10] + ":" + auth[10:] + "@"
}

func (p *proxies) randomMapKeyValue(proxies map[string]*url.URL) (string, *url.URL) {
	r := h.RandomNumber(1, len(proxies))

	i := 1
	for ip, u := range proxies {
		if i == r {
			return ip, u
		}
		i++
	}
	panic("shit happens")
}

func (p *proxies) isCached(ip string) bool {
	_, exists := p.ipCache[ip]
	return exists
}

func (p *proxies) readProxiesFile(path string) (lines []string) {
	file, err := os.Open(p.proxiesPath + "/" + path)
	if err != nil {
		panic("Failed to load " + p.proxiesPath + "/" + path + " proxies")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || p.isCached(line) {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
