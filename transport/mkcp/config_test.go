package mkcp

import (
	"net/url"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.GetMTUValue() != 1350 {
		t.Errorf("expected MTU 1350, got %d", config.GetMTUValue())
	}

	if config.GetTTIValue() != 50 {
		t.Errorf("expected TTI 50, got %d", config.GetTTIValue())
	}

	if config.GetUplinkCapacityValue() != 5 {
		t.Errorf("expected UplinkCapacity 5, got %d", config.GetUplinkCapacityValue())
	}

	if config.GetDownlinkCapacityValue() != 20 {
		t.Errorf("expected DownlinkCapacity 20, got %d", config.GetDownlinkCapacityValue())
	}

	if config.GetWriteBufferSize() != 2*1024*1024 {
		t.Errorf("expected WriteBufferSize 2MB, got %d", config.GetWriteBufferSize())
	}

	if config.GetReadBufferSize() != 2*1024*1024 {
		t.Errorf("expected ReadBufferSize 2MB, got %d", config.GetReadBufferSize())
	}
}

func TestConfigWithCustomValues(t *testing.T) {
	config := &Config{
		MTU:              1400,
		TTI:              20,
		UplinkCapacity:   10,
		DownlinkCapacity: 50,
		WriteBufferSize:  4 * 1024 * 1024,
		ReadBufferSize:   4 * 1024 * 1024,
		Congestion:       true,
		Seed:             "test-seed",
	}

	if config.GetMTUValue() != 1400 {
		t.Errorf("expected MTU 1400, got %d", config.GetMTUValue())
	}

	if config.GetTTIValue() != 20 {
		t.Errorf("expected TTI 20, got %d", config.GetTTIValue())
	}

	if config.GetUplinkCapacityValue() != 10 {
		t.Errorf("expected UplinkCapacity 10, got %d", config.GetUplinkCapacityValue())
	}

	if config.GetDownlinkCapacityValue() != 50 {
		t.Errorf("expected DownlinkCapacity 50, got %d", config.GetDownlinkCapacityValue())
	}
}

func TestGetSendingInFlightSize(t *testing.T) {
	config := DefaultConfig()
	size := config.GetSendingInFlightSize()
	if size < 8 {
		t.Errorf("expected at least 8, got %d", size)
	}
}

func TestGetReceivingInFlightSize(t *testing.T) {
	config := DefaultConfig()
	size := config.GetReceivingInFlightSize()
	if size < 8 {
		t.Errorf("expected at least 8, got %d", size)
	}
}

func TestConfigFromQueryParsesEveryKey(t *testing.T) {
	config, err := ConfigFromQuery(url.Values{
		"mtu":         {"1400"},
		"tti":         {"30"},
		"uplink":      {"7"},
		"downlink":    {"14"},
		"writeBuffer": {"12345"},
		"readBuffer":  {"54321"},
		"congestion":  {"true"},
		"seed":        {"s33d"},
	})
	if err != nil {
		t.Fatalf("ConfigFromQuery: %v", err)
	}
	for _, c := range []struct {
		field string
		got   uint32
		want  uint32
	}{
		{"MTU", config.MTU, 1400},
		{"TTI", config.TTI, 30},
		{"UplinkCapacity", config.UplinkCapacity, 7},
		{"DownlinkCapacity", config.DownlinkCapacity, 14},
		{"WriteBufferSize", config.WriteBufferSize, 12345},
		{"ReadBufferSize", config.ReadBufferSize, 54321},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
		}
	}
	if !config.Congestion {
		t.Error("Congestion = false, want true")
	}
	if config.Seed != "s33d" {
		t.Errorf("Seed = %q, want %q", config.Seed, "s33d")
	}
}

// The camelCase aliases are what v2ray-era subscriptions actually ship, and
// they win over the short key because they are parsed last.
func TestConfigFromQueryCapacityAliases(t *testing.T) {
	config, err := ConfigFromQuery(url.Values{
		"uplink":           {"1"},
		"uplinkCapacity":   {"9"},
		"downlink":         {"2"},
		"downlinkCapacity": {"8"},
	})
	if err != nil {
		t.Fatalf("ConfigFromQuery: %v", err)
	}
	if config.UplinkCapacity != 9 || config.DownlinkCapacity != 8 {
		t.Errorf("uplink/downlink = %d/%d, want 9/8", config.UplinkCapacity, config.DownlinkCapacity)
	}
}

func TestConfigFromQueryKeepsDefaultsWhenEmpty(t *testing.T) {
	got, err := ConfigFromQuery(url.Values{})
	if err != nil {
		t.Fatalf("ConfigFromQuery: %v", err)
	}
	want := DefaultConfig()
	if *got != *want {
		t.Errorf("empty query = %+v, want %+v", *got, *want)
	}
}

// MTU and TTI are divisors in the window-size helpers, and both come from
// subscription links, i.e. from a remote server. Before the range check,
// tti=2000 made 1000/TTI zero and the first dial killed the process.
func TestConfigFromQueryRejectsWindowBreakingValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{"tti above one second", url.Values{"tti": {"2000"}}},
		{"tti zero", url.Values{"tti": {"0"}}},
		{"mtu below the 576 floor", url.Values{"mtu": {"100"}}},
		{"mtu above the 1424 ceiling", url.Values{"mtu": {"9000"}}},
		{"non-numeric mtu", url.Values{"mtu": {"big"}}},
		{"negative tti", url.Values{"tti": {"-1"}}},
		{"bad congestion", url.Values{"congestion": {"maybe"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ConfigFromQuery(tc.query); err == nil {
				t.Fatalf("ConfigFromQuery(%v) = nil error, want rejection", tc.query)
			}
		})
	}
}

// The accepted boundary values must still produce usable windows, i.e. the
// guard has to reject only what would actually break.
func TestWindowSizesSurviveAcceptedBoundaries(t *testing.T) {
	for _, query := range []url.Values{
		{"mtu": {"576"}, "tti": {"1000"}},
		{"mtu": {"1424"}, "tti": {"1"}},
	} {
		config, err := ConfigFromQuery(query)
		if err != nil {
			t.Fatalf("ConfigFromQuery(%v): %v", query, err)
		}
		if config.GetSendingInFlightSize() < 8 {
			t.Errorf("%v: sending in-flight = %d, want >= 8", query, config.GetSendingInFlightSize())
		}
		if config.GetReceivingBufferSize() == 0 {
			t.Errorf("%v: receiving buffer = 0", query)
		}
	}
}

// Why the guard exists, stated as a fact about the arithmetic rather than
// about the parser: a Config built by hand (not from a link) still divides by
// 1000/TTI, so tti>1000 is a runtime error, not merely a bad value.
func TestTTIAboveOneSecondDividesByZero(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("GetSendingInFlightSize with TTI 2000 did not panic; the range check may be removable")
		}
	}()
	(&Config{MTU: 1350, TTI: 2000, UplinkCapacity: 5, WriteBufferSize: 2 << 20}).GetSendingInFlightSize()
}
