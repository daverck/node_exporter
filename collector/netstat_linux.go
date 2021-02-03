// Copyright 2015 The Prometheus Authors
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

// +build !nonetstat

package collector

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	netStatsSubsystem = "netstat"
)

var (
	netStatFields = kingpin.Flag("collector.netstat.fields", "Regexp of fields to return for netstat collector.").Default("^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans)|Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)|Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors)|IpLocalPortRange?_(min|max)|TcpSocket?_(NbUsedPort)|UdpSocket?_(NbUsedPort))$").String()
)

type netStatCollector struct {
	fieldPattern *regexp.Regexp
	logger       log.Logger
}
type ephemeralPortTuple struct {
	localIP    string
	remoteIP   string
	remotePort string
}

func init() {
	registerCollector("netstat", defaultEnabled, NewNetStatCollector)
}

// NewNetStatCollector takes and returns
// a new Collector exposing network stats.
func NewNetStatCollector(logger log.Logger) (Collector, error) {
	pattern := regexp.MustCompile(*netStatFields)
	return &netStatCollector{
		fieldPattern: pattern,
		logger:       logger,
	}, nil
}

func (c *netStatCollector) Update(ch chan<- prometheus.Metric) error {
	netStats, err := getNetStats(procFilePath("net/netstat"))
	if err != nil {
		return fmt.Errorf("couldn't get netstats: %w", err)
	}
	snmpStats, err := getNetStats(procFilePath("net/snmp"))
	if err != nil {
		return fmt.Errorf("couldn't get SNMP stats: %w", err)
	}
	snmp6Stats, err := getSNMP6Stats(procFilePath("net/snmp6"))
	if err != nil {
		return fmt.Errorf("couldn't get SNMP6 stats: %w", err)
	}
	ipLocalPortRangeStats, err := getIPLocalPortRange(procFilePath("sys/net/ipv4/ip_local_port_range"))
	if err != nil {
		return fmt.Errorf("couldn't get ip local port range stats: %w", err)
	}
	tcpSocketsStats, err := getSocketsStats(procFilePath("net/tcp"))
	if err != nil {
		return fmt.Errorf("couldn't get tcp socket stats: %w", err)
	}
	udpSocketsStats, err := getSocketsStats(procFilePath("net/udp"))
	if err != nil {
		return fmt.Errorf("couldn't get udp socket stats: %w", err)
	}

	// Merge the results of snmpStats into netStats (collisions are possible, but
	// we know that the keys are always unique for the given use case).
	for k, v := range snmpStats {
		netStats[k] = v
	}
	for k, v := range snmp6Stats {
		netStats[k] = v
	}
	for k, v := range ipLocalPortRangeStats {
		netStats[k] = v
	}
	for protocol, protocolStats := range netStats {
		for name, value := range protocolStats {
			key := protocol + "_" + name
			v, err := strconv.ParseFloat(value, 64)
			if err != nil {
				fmt.Printf("invalid value %s in netstats", value)
				return fmt.Errorf("invalid value %s in netstats: %w", value, err)
			}
			if !c.fieldPattern.MatchString(key) {
				continue
			}
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, netStatsSubsystem, key),
					fmt.Sprintf("Statistic %s.", protocol+name),
					nil, nil,
				),
				prometheus.UntypedValue, v,
			)
		}
	}

	// Merge the results of udpSocketsStats into tcpSocketsStats
	for k, v := range udpSocketsStats {
		tcpSocketsStats[k] = v
	}
	for protocol, protocolStats := range tcpSocketsStats {
		for name, v := range protocolStats {
			key := protocol + "_" + name
			if !c.fieldPattern.MatchString(key) {
				continue
			}
			for tupleForEphemeralPort, value := range v {
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, netStatsSubsystem, key),
						fmt.Sprintf("Statistic %s.", protocol+name),
						[]string{"localIp", "remoteIp", "remotePort"},
						nil,
					),
					prometheus.CounterValue,
					float64(value),
					tupleForEphemeralPort.localIP, tupleForEphemeralPort.remoteIP, tupleForEphemeralPort.remotePort,
				)
			}
		}
	}

	return nil
}

func getNetStats(fileName string) (map[string]map[string]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseNetStats(file, fileName)
}

func parseNetStats(r io.Reader, fileName string) (map[string]map[string]string, error) {
	var (
		netStats = map[string]map[string]string{}
		scanner  = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		nameParts := strings.Split(scanner.Text(), " ")
		scanner.Scan()
		valueParts := strings.Split(scanner.Text(), " ")
		// Remove trailing :.
		protocol := nameParts[0][:len(nameParts[0])-1]
		netStats[protocol] = map[string]string{}
		if len(nameParts) != len(valueParts) {
			return nil, fmt.Errorf("mismatch field count mismatch in %s: %s",
				fileName, protocol)
		}
		for i := 1; i < len(nameParts); i++ {
			netStats[protocol][nameParts[i]] = valueParts[i]
		}
	}

	return netStats, scanner.Err()
}

func getSNMP6Stats(fileName string) (map[string]map[string]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		// On systems with IPv6 disabled, this file won't exist.
		// Do nothing.
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}
	defer file.Close()

	return parseSNMP6Stats(file)
}

func parseSNMP6Stats(r io.Reader) (map[string]map[string]string, error) {
	var (
		netStats = map[string]map[string]string{}
		scanner  = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		stat := strings.Fields(scanner.Text())
		if len(stat) < 2 {
			continue
		}
		// Expect to have "6" in metric name, skip line otherwise
		if sixIndex := strings.Index(stat[0], "6"); sixIndex != -1 {
			protocol := stat[0][:sixIndex+1]
			name := stat[0][sixIndex+1:]
			if _, present := netStats[protocol]; !present {
				netStats[protocol] = map[string]string{}
			}
			netStats[protocol][name] = stat[1]
		}
	}

	return netStats, scanner.Err()
}

//get ephemeral ports range
func getIPLocalPortRange(fileName string) (map[string]map[string]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}
	defer file.Close()

	return parseIPLocalPortRange(file)
}

func parseIPLocalPortRange(r io.Reader) (map[string]map[string]string, error) {
	var (
		ipLocalPortRange = map[string]map[string]string{}
		scanner          = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		stat := strings.Fields(scanner.Text())
		name := "IpLocalPortRange"
		ipLocalPortRange[name] = map[string]string{}
		ipLocalPortRange[name]["min"] = stat[0]
		ipLocalPortRange[name]["max"] = stat[1]
	}

	return ipLocalPortRange, scanner.Err()
}

func getSocketsStats(fileName string) (map[string]map[string]map[ephemeralPortTuple]int, error) {
	file, err := os.Open(fileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}
	defer file.Close()

	return parseSocketsStats(file, fileName)
}

func parseSocketsStats(r io.Reader, fileName string) (map[string]map[string]map[ephemeralPortTuple]int, error) {
	var (
		socketsStats = map[string]map[string]map[ephemeralPortTuple]int{}
		scanner      = bufio.NewScanner(r)
		name         string
	)

	// Expect to have "tcp" or "udp" in fileName, return error otherwise
	if strings.Contains(fileName, "tcp") {
		name = "TcpSocket"
	} else if strings.Contains(fileName, "udp") {
		name = "UdpSocket"
	} else {
		return nil, fmt.Errorf("fileName (%v) should contain either \"tcp\" or \"udp\"", fileName)
	}
	socketsStats[name] = map[string]map[ephemeralPortTuple]int{}
	socketsStats[name]["NbUsedPort"] = map[ephemeralPortTuple]int{}

	if scanner.Scan() {
		for scanner.Scan() {
			stat := strings.Fields(scanner.Text())

			// check file format
			if len(stat) < 10 || len(strings.Split(stat[1], ":")) != 2 || len(strings.Split(stat[2], ":")) != 2 {
				return nil, fmt.Errorf("file (%s) is not formatted as expected %v", fileName, len(stat))
			}

			// parse IP adresses and ports numbers
			localAddressBytes, err := hex.DecodeString(strings.Split(stat[1], ":")[0])
			if err != nil {
				panic(err)
			}
			remoteAddressBytes, err := hex.DecodeString(strings.Split(stat[2], ":")[0])
			if err != nil {
				panic(err)
			}
			remotePortBytes, err := hex.DecodeString(strings.Split(stat[2], ":")[1])
			if err != nil {
				panic(err)
			}
			localAddress := fmt.Sprintf("%v.%v.%v.%v", localAddressBytes[0], localAddressBytes[1], localAddressBytes[2], localAddressBytes[3])
			remoteAddress := fmt.Sprintf("%v.%v.%v.%v", remoteAddressBytes[0], remoteAddressBytes[1], remoteAddressBytes[2], remoteAddressBytes[3])
			remotePort := fmt.Sprintf("%v%v", remotePortBytes[0], remotePortBytes[1])

			tupleForEphemeralPort := ephemeralPortTuple{localIP: localAddress,
				remoteIP:   remoteAddress,
				remotePort: remotePort}

			// increment socket count for set of local address
			if _, exist := socketsStats[name]["NbUsedPort"][tupleForEphemeralPort]; exist {
				socketsStats[name]["NbUsedPort"][tupleForEphemeralPort]++
			} else {
				socketsStats[name]["NbUsedPort"][tupleForEphemeralPort] = 1
			}

		}
	}

	return socketsStats, scanner.Err()
}
