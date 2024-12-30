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

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

type vendorModels struct {
	VendorName string `yaml:"vendorName"`
	VendorID   string `yaml:"vendorID"`
	Models     []struct {
		PciID     string `yaml:"pciID"`
		ModelName string `yaml:"modelName"`
	} `yaml:"models"`
}

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
	pciDevicesPath    string
	logger            log.Logger
	vendorToDeviceMap map[string]vendorData
}

var (
	mappingFile = kingpin.Flag("collector.accelerators.mapping-file", "Path to the mapped accelerators data config.").Default(
		"/var/node_exporter/accelerators_collector_config/config.yaml").String()
	acceleratorCardsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "accelerator", "card_info"),
		"Accelerator card info including vendor, model and pci id (address)",
		[]string{"vendor", "model", "id"}, nil,
	)
)

func init() {
	registerCollector("accelerator", defaultEnabled, NewAcceleratorCollector)
}

// NewAcceleratorCollector returns a new Collector exposing accelerator cards count.
func NewAcceleratorCollector(logger log.Logger) (Collector, error) {
	vendorToDeviceMap, err := prepareVendorModelData(*mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get the accelerator configuration: %v", err)
	}
	return &acceleratorsCollector{
		pciDevicesPath:    filepath.Join(*sysPath, "bus/pci/devices"),
		logger:            logger,
		vendorToDeviceMap: vendorToDeviceMap,
	}, nil
}

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

		cardData, isMonitored := a.isMonitoredAccelerator(vendorID, deviceID, pciID)
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

func (a *acceleratorsCollector) isMonitoredAccelerator(vendor, device, pciID string) (cardData, bool) {
	vendorData, ok := a.vendorToDeviceMap[vendor]
	if !ok {
		return cardData{}, false
	}

	deviceDesc, ok := vendorData.devicesIDs[device]
	if !ok {
		return cardData{}, false
	}
	return cardData{vendorData.vendorName, deviceDesc, pciID}, true
}

func prepareVendorModelData(mappingFilePath string) (map[string]vendorData, error) {
	yamlStr, err := os.ReadFile(mappingFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open accelerators config file %s: %v", mappingFilePath, err)
	}
	var vendorsModelsConfig []vendorModels
	err = yaml.UnmarshalStrict(yamlStr, &vendorsModelsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal accelerators config data: %v", err)
	}
	vendorToDeviceMap := make(map[string]vendorData, len(vendorsModelsConfig))

	for _, vendorModelsConfig := range vendorsModelsConfig {
		if _, ok := vendorToDeviceMap[vendorModelsConfig.VendorID]; ok {
			return nil, fmt.Errorf("mapping file contains duplicate of vendor id %s", vendorModelsConfig.VendorID)
		}
		devicesIDs := make(map[string]string, len(vendorModelsConfig.Models))
		for _, model := range vendorModelsConfig.Models {
			if _, ok := devicesIDs[model.PciID]; ok {
				return nil, fmt.Errorf("mapping file contains duplicate of device id %s for vendor id %s", model.PciID, vendorModelsConfig.VendorID)
			}
			devicesIDs[model.PciID] = model.ModelName
		}
		vendorToDeviceMap[vendorModelsConfig.VendorID] = vendorData{
			vendorName: vendorModelsConfig.VendorName,
			devicesIDs: devicesIDs,
		}

	}

	return vendorToDeviceMap, nil
}
