// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nonetdev

package collector

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"strconv"

	"golang.org/x/sys/unix"
	"regexp"
	"unsafe"
)

func getNetDevStats(ignore *regexp.Regexp, accept *regexp.Regexp, logger log.Logger) (map[string]map[string]string, error) {
	netDev := map[string]map[string]string{}

	mib := [6]_C_int{unix.CTL_NET, unix.AF_ROUTE, 0, 0, unix.NET_RT_IFLIST, 0}
	buf, err := sysctl(mib[:])
	if err != nil {
		return nil, err
	}
	n := uintptr(len(buf))
	index := uintptr(unsafe.Pointer(&buf[0]))
	next := uintptr(0)

	var rtm *unix.RtMsghdr

	for next = index; next < (index + n); next += uintptr(rtm.Msglen) {
		rtm = (*unix.RtMsghdr)(unsafe.Pointer(next))
		if rtm.Version != unix.RTM_VERSION || rtm.Type != unix.RTM_IFINFO {
			continue
		}
		ifm := (*unix.IfMsghdr)(unsafe.Pointer(next))
		if ifm.Addrs&unix.RTA_IFP == 0 {
			continue
		}
		dl := (*unix.RawSockaddrDatalink)(unsafe.Pointer(next + uintptr(rtm.Hdrlen)))
		if dl.Family != unix.AF_LINK {
			continue
		}
		data := ifm.Data
		dev := int8ToString(dl.Data[:dl.Nlen])
		if ignore != nil && ignore.MatchString(dev) {
			level.Debug(logger).Log("msg", "Ignoring device", "device", dev)
			continue
		}
		if accept != nil && !accept.MatchString(dev) {
			level.Debug(logger).Log("msg", "Ignoring device", "device", dev)
			continue
		}

		netDev[dev] = map[string]string{
			"receive_packets":    strconv.Itoa(int(data.Ipackets)),
			"transmit_packets":   strconv.Itoa(int(data.Opackets)),
			"receive_errs":       strconv.Itoa(int(data.Ierrors)),
			"transmit_errs":      strconv.Itoa(int(data.Oerrors)),
			"receive_bytes":      strconv.Itoa(int(data.Ibytes)),
			"transmit_bytes":     strconv.Itoa(int(data.Obytes)),
			"receive_multicast":  strconv.Itoa(int(data.Imcasts)),
			"transmit_multicast": strconv.Itoa(int(data.Omcasts)),
			"receive_drop":       strconv.Itoa(int(data.Iqdrops)),
		}
	}
	return netDev, nil
}