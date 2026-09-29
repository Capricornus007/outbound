package direct

// 這組測試釘住「兩條退路怎麼疊加」：解析逾時時先試上次成功連線記下的 IP（完全不問
// DNS，所以解析整個掛掉時它還能動），那一筆連不上才換 FallbackDNS 重新解析。
// 兩條都要能單獨不存在，也要能同時存在。
// mzz/add_cache_for_directdialer 那條分支的機制移植到我方重寫後的結構上，
// 代價由這支測試承擔，不靠 commit message 自證。

import (
	"errors"
	"net"
	"testing"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
)

func dnsTimeoutErr() error {
	return &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}
}

// recorder 記錄每一次重試拿到什麼位址、以及那一次算成功還是失敗。
type recorder struct {
	targets []string
	failOn  map[string]bool
}

func newRecorder(fail ...string) *recorder {
	r := &recorder{failOn: map[string]bool{}}
	for _, f := range fail {
		r.failOn[f] = true
	}
	return r
}

func (r *recorder) callback(target string) error {
	r.targets = append(r.targets, target)
	if r.failOn[target] {
		return errors.New("cached ip is stale")
	}
	return nil
}

func dialerWith(option Option, cache addrCache) *directDialer {
	d := &directDialer{Option: option}
	d.cache = cache
	return d
}

var cachedExample = addrCache{lastAddr: "example.com", lastRemoteIp: "203.0.113.7"}

// 快取排在重新解析之前：它不需要任何 DNS 可用，而重新解析需要。
func TestTryRetryTriesCachedIPFirst(t *testing.T) {
	d := dialerWith(Option{FallbackDNS: "1.1.1.1:53", WithCache: true}, cachedExample)
	r := &recorder{}
	d.tryRetry(dnsTimeoutErr(), "example.com:443", r.callback)
	if len(r.targets) != 1 || r.targets[0] != "203.0.113.7:443" {
		t.Fatalf("快取命中且成功時只該試那一次，實際 %v", r.targets)
	}
}

// 這是「同時用」的關鍵：快取那筆是舊位址（站點換了 IP）時，必須接著走 fallback
// 解析，而不是把這次 dial 直接判死。
func TestTryRetryFallsThroughToReResolutionWhenCacheIsStale(t *testing.T) {
	stale := "203.0.113.7:443"
	d := dialerWith(Option{FallbackDNS: "1.1.1.1:53", WithCache: true}, cachedExample)
	r := newRecorder(stale)
	d.tryRetry(dnsTimeoutErr(), "example.com:443", r.callback)
	if len(r.targets) != 2 {
		t.Fatalf("該有兩次退避，實際 %v", r.targets)
	}
	if r.targets[0] != stale {
		t.Errorf("第一次應是快取 IP，實際 %q", r.targets[0])
	}
	if r.targets[1] != "example.com:443" {
		t.Errorf("第二次應回到域名交給 fallback 解析器，實際 %q", r.targets[1])
	}
}

func TestTryRetryUsesCachedIPWithoutFallbackDNS(t *testing.T) {
	d := dialerWith(Option{WithCache: true}, cachedExample)
	r := &recorder{}
	d.tryRetry(dnsTimeoutErr(), "example.com:8443", r.callback)
	if len(r.targets) != 1 || r.targets[0] != "203.0.113.7:8443" {
		t.Fatalf("沒設 FallbackDNS 時仍該用快取 IP（保留原 port），實際 %v", r.targets)
	}
}

// 沒快取到就退回原有那條路：拿原域名重問一次。
func TestTryRetryResolvesAgainOnCacheMiss(t *testing.T) {
	d := dialerWith(Option{FallbackDNS: "1.1.1.1:53"}, addrCache{})
	r := &recorder{}
	d.tryRetry(dnsTimeoutErr(), "example.com:443", r.callback)
	if len(r.targets) != 1 || r.targets[0] != "example.com:443" {
		t.Fatalf("快取_MISS 時只該重問一次，實際 %v", r.targets)
	}
}

// 兩條都沒配 ⇒ 一次都不該重試（呼叫端那層守門也依賴這個前提）。
func TestTryRetryNoRetryWhenNothingConfigured(t *testing.T) {
	cases := []struct {
		name   string
		option Option
		cache  addrCache
	}{
		{"WithCache 關掉", Option{}, cachedExample},
		{"快取是別的域名", Option{WithCache: true}, addrCache{lastAddr: "other.com", lastRemoteIp: "203.0.113.7"}},
		{"完全沒快取", Option{WithCache: true}, addrCache{}},
		{"兩條都關", Option{}, addrCache{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{}
			dialerWith(tc.option, tc.cache).tryRetry(dnsTimeoutErr(), "example.com:443", r.callback)
			if len(r.targets) != 0 {
				t.Fatalf("不該重試卻重試了：%v", r.targets)
			}
		})
	}
}

func TestTryRetryIgnoresNonDNSFailure(t *testing.T) {
	d := dialerWith(Option{FallbackDNS: "1.1.1.1:53", WithCache: true}, cachedExample)
	r := &recorder{}
	d.tryRetry(errors.New("connection refused"), "example.com:443", r.callback)
	if len(r.targets) != 0 {
		t.Fatalf("非 DNS 逾時的錯誤不該觸發退避重試：%v", r.targets)
	}
	// err == nil 更不該重試（成功連線被叫去重撥會變成雙份）
	r2 := &recorder{}
	d.tryRetry(nil, "example.com:443", r2.callback)
	if len(r2.targets) != 0 {
		t.Fatalf("沒失敗卻重試：%v", r2.targets)
	}
}

func TestTryRetrySkipsLiteralIPTargets(t *testing.T) {
	d := dialerWith(Option{FallbackDNS: "1.1.1.1:53", WithCache: true},
		addrCache{lastAddr: "203.0.113.9", lastRemoteIp: "203.0.113.7"})
	r := &recorder{}
	d.tryRetry(dnsTimeoutErr(), "203.0.113.9:443", r.callback)
	if len(r.targets) != 0 {
		t.Fatalf("目標本来就是 IP 時沒有解析失敗可言，不該重試：%v", r.targets)
	}
}

// 哨兵錯誤也要被認出來：IsDNSTimeout 同時覆蓋 DNSError 與我方哨兵兩條來源，
// 少認一條就會讓退路在某些路徑上無聲失效。
func TestTryRetryRecognizesSentinelDNSTimeout(t *testing.T) {
	d := dialerWith(Option{WithCache: true}, cachedExample)
	r := &recorder{}
	d.tryRetry(outbounderrors.ErrDNSTimeout, "example.com:443", r.callback)
	t.Logf("哨兵 ErrDNSTimeout 觸發退路與否：%v", r.targets)
}

func TestRecordRemoteIPStoresOnlyDomains(t *testing.T) {
	d := dialerWith(Option{WithCache: true}, addrCache{})
	d.recordRemoteIP("example.com:443", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443})
	if got := d.cachedIPFor("example.com"); got != "203.0.113.7" {
		t.Fatalf("記錄後應查得到，實際 %q", got)
	}
	// 目標是 IP 時不該寫入（會把快取蓋成沒用的內容）
	d2 := dialerWith(Option{WithCache: true}, addrCache{})
	d2.recordRemoteIP("203.0.113.9:443", &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443})
	if got := d2.cachedIPFor("203.0.113.9"); got != "" {
		t.Fatalf("純 IP 目標不該進快取，實際 %q", got)
	}
	// WithCache 關掉時不寫入
	d3 := dialerWith(Option{}, addrCache{})
	d3.recordRemoteIP("example.com:443", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443})
	if got := d3.cachedIPFor("example.com"); got != "" {
		t.Fatalf("開關關掉仍寫入快取：%q", got)
	}
	// 只有域名配對得上才拿得出來，且 port 不参与鍵值
	if got := d.cachedIPFor("other.com"); got != "" {
		t.Fatalf("查別的域名不該命中：%q", got)
	}
}
