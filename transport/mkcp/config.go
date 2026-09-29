// Package mkcp provides mKCP transport implementation.
// mKCP is a KCP (A Fast and Reliable ARQ Protocol) based transport.
//
// Acknowledgement:
//   - skywind3000@github for inventing the KCP protocol
//   - xtaci@github for translating to Golang
//   - v2fly/v2ray-core for the reference implementation
package mkcp

import (
	"crypto/cipher"
	"fmt"
	"net/url"
	"strconv"
)

// Config contains mKCP configuration parameters.
type Config struct {
	// MTU is the Maximum Transmission Unit. Default is 1350.
	MTU uint32
	// TTI is Transmission Time Interval in milliseconds. Default is 50.
	TTI uint32
	// UplinkCapacity is the uplink capacity in MB/s. Default is 5.
	UplinkCapacity uint32
	// DownlinkCapacity is the downlink capacity in MB/s. Default is 20.
	DownlinkCapacity uint32
	// WriteBufferSize is the write buffer size in bytes. Default is 2MB.
	WriteBufferSize uint32
	// ReadBufferSize is the read buffer size in bytes. Default is 2MB.
	ReadBufferSize uint32
	// Congestion enables congestion control. Default is false.
	Congestion bool
	// Seed is the encryption seed. If empty, uses SimpleAuthenticator.
	Seed string
}

// DefaultConfig returns a default mKCP configuration.
func DefaultConfig() *Config {
	return &Config{
		MTU:              1350,
		TTI:              50,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		WriteBufferSize:  2 * 1024 * 1024,
		ReadBufferSize:   2 * 1024 * 1024,
		Congestion:       false,
		Seed:             "",
	}
}

// ConfigFromQuery builds a Config from a link's query parameters, starting
// from DefaultConfig. Shared by the mkcp:// link creator and mekya://, whose
// KCP parameters ride on the same key names.
//
// MTU and TTI are range-checked, not merely parsed: both become divisors
// (1000/TTI in the in-flight sizes, MTU in the buffer sizes and in mss), and
// these values come from subscription links, i.e. from a remote server. An
// out-of-range pair used to take the whole process down with an integer
// divide-by-zero on the first dial.
func ConfigFromQuery(query url.Values) (*Config, error) {
	config := DefaultConfig()

	// Parse MTU
	if mtuStr := query.Get("mtu"); mtuStr != "" {
		mtu, err := strconv.ParseUint(mtuStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid mtu: %w", err)
		}
		if mtu < 576 || mtu > 1424 {
			return nil, fmt.Errorf("invalid mtu: %d out of range [576, 1424]", mtu)
		}
		config.MTU = uint32(mtu)
	}

	// Parse TTI
	if ttiStr := query.Get("tti"); ttiStr != "" {
		tti, err := strconv.ParseUint(ttiStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid tti: %w", err)
		}
		if tti < 1 || tti > 1000 {
			return nil, fmt.Errorf("invalid tti: %d out of range [1, 1000]", tti)
		}
		config.TTI = uint32(tti)
	}

	// Parse Uplink Capacity
	if uplinkStr := query.Get("uplink"); uplinkStr != "" {
		uplink, err := strconv.ParseUint(uplinkStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid uplink: %w", err)
		}
		config.UplinkCapacity = uint32(uplink)
	}
	if uplinkStr := query.Get("uplinkCapacity"); uplinkStr != "" {
		uplink, err := strconv.ParseUint(uplinkStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid uplinkCapacity: %w", err)
		}
		config.UplinkCapacity = uint32(uplink)
	}

	// Parse Downlink Capacity
	if downlinkStr := query.Get("downlink"); downlinkStr != "" {
		downlink, err := strconv.ParseUint(downlinkStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid downlink: %w", err)
		}
		config.DownlinkCapacity = uint32(downlink)
	}
	if downlinkStr := query.Get("downlinkCapacity"); downlinkStr != "" {
		downlink, err := strconv.ParseUint(downlinkStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid downlinkCapacity: %w", err)
		}
		config.DownlinkCapacity = uint32(downlink)
	}

	// Parse Write Buffer Size
	if writeBufferStr := query.Get("writeBuffer"); writeBufferStr != "" {
		writeBuffer, err := strconv.ParseUint(writeBufferStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid writeBuffer: %w", err)
		}
		config.WriteBufferSize = uint32(writeBuffer)
	}

	// Parse Read Buffer Size
	if readBufferStr := query.Get("readBuffer"); readBufferStr != "" {
		readBuffer, err := strconv.ParseUint(readBufferStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid readBuffer: %w", err)
		}
		config.ReadBufferSize = uint32(readBuffer)
	}

	// Parse Congestion
	if congestionStr := query.Get("congestion"); congestionStr != "" {
		congestion, err := strconv.ParseBool(congestionStr)
		if err != nil {
			return nil, fmt.Errorf("invalid congestion: %w", err)
		}
		config.Congestion = congestion
	}

	// Parse Seed
	config.Seed = query.Get("seed")

	return config, nil
}

// GetMTUValue returns the value of MTU settings.
func (c *Config) GetMTUValue() uint32 {
	if c == nil || c.MTU == 0 {
		return 1350
	}
	return c.MTU
}

// GetTTIValue returns the value of TTI settings.
func (c *Config) GetTTIValue() uint32 {
	if c == nil || c.TTI == 0 {
		return 50
	}
	return c.TTI
}

// GetUplinkCapacityValue returns the value of UplinkCapacity settings.
func (c *Config) GetUplinkCapacityValue() uint32 {
	if c == nil || c.UplinkCapacity == 0 {
		return 5
	}
	return c.UplinkCapacity
}

// GetDownlinkCapacityValue returns the value of DownlinkCapacity settings.
func (c *Config) GetDownlinkCapacityValue() uint32 {
	if c == nil || c.DownlinkCapacity == 0 {
		return 20
	}
	return c.DownlinkCapacity
}

// GetWriteBufferSize returns the size of WriteBuffer in bytes.
func (c *Config) GetWriteBufferSize() uint32 {
	if c == nil || c.WriteBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBufferSize
}

// GetReadBufferSize returns the size of ReadBuffer in bytes.
func (c *Config) GetReadBufferSize() uint32 {
	if c == nil || c.ReadBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.ReadBufferSize
}

// GetSecurity returns the security AEAD cipher.
func (c *Config) GetSecurity() (cipher.AEAD, error) {
	if c != nil && c.Seed != "" {
		return NewAEADAESGCMBasedOnSeed(c.Seed), nil
	}
	return NewSimpleAuthenticator(), nil
}

// GetSendingInFlightSize calculates the sending in-flight window size.
func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.GetUplinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

// GetSendingBufferSize calculates the sending buffer size in segments.
func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

// GetReceivingInFlightSize calculates the receiving in-flight window size.
func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.GetDownlinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

// GetReceivingBufferSize calculates the receiving buffer size in segments.
func (c *Config) GetReceivingBufferSize() uint32 {
	return c.GetReadBufferSize() / c.GetMTUValue()
}
