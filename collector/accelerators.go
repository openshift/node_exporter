// Copyright 2024 The Prometheus Authors
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

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type cardData struct {
	vendor string
	model  string
	id     string
}

type vendorData struct {
	vendorName string
	devicesIDs map[string]string
}

type acceleratorsCollector struct {
	pciDevicesPath string
	logger         log.Logger
}

func init() {
	registerCollector("accelerator", defaultEnabled, NewAcceleratorCollector)
}

// NewAcceleratorCollector returns a new Collector exposing accelerator cards count.
func NewAcceleratorCollector(logger log.Logger) (Collector, error) {
	return &acceleratorsCollector{
		pciDevicesPath: filepath.Join(*sysPath, "bus/pci/devices"),
		logger:         logger,
	}, nil
}

var (
	acceleratorCardsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "accelerator", "card_info"),
		"Accelerator card info including vendor, model and pci id (address)",
		[]string{"vendor", "model", "id"}, nil,
	)

	nvidiaDeviceIDsMap = map[string]string{
		"0x20f5": "NVIDIA A800 PCIe 80GB",
		"0x20f6": "NVIDIA A800 40GB PCIe active cooled",
		"0x20fd": "NVIDIA AX800",
		"0x20f1": "NVIDIA A100 PCIe 40GB",
		"0x20b5": "NVIDIA A100 PCIe 80GB",
		"0x2235": "NVIDIA A40",
		"0x20b7": "NVIDIA A30",
		"0x2236": "NVIDIA A10",
		"0x25b6": "NVIDIA A16",
		"0x2322": "H800 NVL",
		"0x2321": "NVIDIA H100 NVL",
		"0x2331": "NVIDIA H100 PCIe 80GB",
		"0x26b5": "NVIDIA L40",
		"0x26b9": "NVIDIA L40S",
		"0x26bA": "NVIDIA L20 liquid cooled",
		"0x27b8": "NVIDIA L4",
		"0x27b6": "NVIDIA L2",
		"0x26b1": "NVIDIA RTX 6000 Ada",
		"0x26b3": "NVIDIA RTX 5880 Ada",
		"0x2231": "NVIDIA RTX 5000 Ada",
		"0x2230": "NVIDIA RTX A6000",
		"0x2233": "NVIDIA RTX A5500",
		"0x1e30": "NVIDIA RTX 8000 passive",
		"0x2531": "NVIDIA RTX A2000",
		"0x20b0": "NVIDIA A100 SXM4 40G",
		"0x233a": "NVIDIA H800 NVL",
		"0x233b": "NVIDIA H200 NVL",
		"0x20b2": "NVIDIA A100SXM4 80GB",
		"0x20b3": "NVIDIA A100 SXM 64GB",
		"0x20bd": "NVIDIA A800 SXM4 40GB",
		"0x20f3": "NVIDIA A800 SXM4 80GB",
		"0x25b0": "NVIDIA RTX A1000",
	}

	amdDeviceIDsMap = map[string]string{
		"0x740f": "AMD MI210",
		"0x740c": "AMD MI250",
		"0x7408": "AMD MI250X",
		"0x74a0": "AMD MI300",
		"0x74a1": "AMD MI300X",
		"0x74a5": "AMD MI325X",
		"0x7aa2": "AMD MI308X",
		"0x74b5": "AMD MI300X VF",
		"0x7410": "AMD MI210 VF",
	}

	gaudiDeviceIDsMap = map[string]string{
		"0x1000": "Gaudi 1",
		"0x1020": "Gaudi 2",
	}

	intelDeviceIDsMap = map[string]string{
		"0x0bd5": "Intel Data Center GPU Max 1550",
		"0x0bda": "Intel Data Center GPU Max 1100",
		"0x56c0": "Intel Data Center GPU Flex 170",
		"0x56c1": "Intel Data Center GPU Flex 140",
	}

	qualcommDeviceIDsMap = map[string]string{
		"0xa100": "Qualcomm AI 100",
		"0xa080": "Qualcomm AI 80",
	}

	// vendor map, add any new vendor to this map
	vendorToDeviceMap = map[string]vendorData{
		// nvidia devices
		"0x10de": vendorData{"NVIDIA", nvidiaDeviceIDsMap},
		// amd devices
		"0x1002": vendorData{"AMD", amdDeviceIDsMap},
		// gaudi devices
		"0x1da3": vendorData{"GAUDI", gaudiDeviceIDsMap},
		// intel devices
		"0x8086": vendorData{"INTEL", intelDeviceIDsMap},
		// qualcomm devices
		"0x17cb": vendorData{"QUALCOMM", qualcommDeviceIDsMap},
	}
)

func (a *acceleratorsCollector) Update(ch chan<- prometheus.Metric) error {
	pciDevices, err := os.ReadDir(a.pciDevicesPath)
	if err != nil {
		return fmt.Errorf("failed to read from  %q: %w", a.pciDevicesPath, err)
	}

	for _, pciDevice := range pciDevices {
		pciID := pciDevice.Name()
		vendorID, err := a.getVendorID(pciID)
		if err != nil {
			level.Error(a.logger).Log("msg", "failed to get pci vendor ID", "name", pciDevice.Name(), "err", err)
			continue
		}
		deviceID, err := a.getDeviceID(pciID)
		if err != nil {
			level.Error(a.logger).Log("msg", "failed to get pci device ID", "name", pciDevice.Name(), "err", err)
			continue
		}

		level.Debug(a.logger).Log("msg", "checking pci device", "vendor", vendorID, "device", deviceID)

		cardData, isMonitored := isMonitoredAccelerator(vendorID, deviceID, pciID)
		if !isMonitored {
			continue
		}
		level.Debug(a.logger).Log("msg", "accelerator device found", "vendor", cardData.vendor, "model", cardData.model)
		ch <- prometheus.MustNewConstMetric(acceleratorCardsDesc, prometheus.CounterValue, float64(1), cardData.vendor, cardData.model, cardData.id)
	}

	return nil
}

func (a *acceleratorsCollector) getVendorID(pciID string) (string, error) {
	return a.getPCIFileData(pciID, "vendor")
}

func (a *acceleratorsCollector) getDeviceID(pciID string) (string, error) {
	return a.getPCIFileData(pciID, "device")
}

func (a *acceleratorsCollector) getPCIFileData(pciID, fileName string) (string, error) {
	pciFilePath := filepath.Join(a.pciDevicesPath, pciID, fileName)
	data, err := os.ReadFile(pciFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", pciFilePath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func isMonitoredAccelerator(vendor, device, pciID string) (cardData, bool) {
	vendorData, ok := vendorToDeviceMap[vendor]
	if !ok {
		return cardData{}, false
	}

	deviceDesc, ok := vendorData.devicesIDs[device]
	if !ok {
		return cardData{}, false
	}
	return cardData{vendorData.vendorName, deviceDesc, pciID}, true
}
