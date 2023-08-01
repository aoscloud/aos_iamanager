// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config_test

import (
	"encoding/json"
	"log"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/aoscloud/aos_common/aoserrors"

	"github.com/aoscloud/aos_iamanager/config"
)

/*******************************************************************************
 * Vars
 ******************************************************************************/

var (
	cfg    *config.Config
	tmpDir string
)

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		log.Fatalf("Setup error: %s", err)
	}

	ret := m.Run()

	if err := cleanup(); err != nil {
		log.Fatalf("Cleanup error: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestGetCredentials(t *testing.T) {
	if cfg.IAMProtectedServerURL != "localhost:8089" {
		t.Errorf("Wrong protected server URL value: %s", cfg.IAMProtectedServerURL)
	}

	if cfg.IAMPublicServerURL != "localhost:8090" {
		t.Errorf("Wrong public server URL value: %s", cfg.IAMPublicServerURL)
	}

	if cfg.CACert != "/etc/ssl/certs/rootCA.crt" {
		t.Errorf("Wrong cert value: %s", cfg.CACert)
	}

	if cfg.CertStorage != "/var/aos/crypt/iam/" {
		t.Errorf("Wrong key value: %s", cfg.CertStorage)
	}
}

func TestGetWorkingDir(t *testing.T) {
	if cfg.WorkingDir != "/var/aos/iamanager" {
		t.Errorf("Wrong working dir value: %s", cfg.WorkingDir)
	}
}

func TestModules(t *testing.T) {
	if len(cfg.CertModules) != 3 {
		t.Fatalf("Wrong modules len: %d", len(cfg.CertModules))
	}

	if cfg.CertModules[0].ID != "id1" || cfg.CertModules[1].ID != "id2" || cfg.CertModules[2].ID != "id3" {
		t.Error("Wrong module id")
	}

	if cfg.CertModules[0].Plugin != "test1" || cfg.CertModules[1].Plugin != "test2" ||
		cfg.CertModules[2].Plugin != "test3" {
		t.Error("Wrong plugin value")
	}

	if cfg.CertModules[0].Algorithm != "rsa" || cfg.CertModules[1].Algorithm != "ecc" ||
		cfg.CertModules[2].Algorithm != "rsa" {
		t.Error("Wrong plugin value")
	}

	if cfg.CertModules[0].MaxItems != 1 || cfg.CertModules[1].MaxItems != 2 || cfg.CertModules[2].MaxItems != 3 {
		t.Error("Wrong max items value")
	}

	if cfg.CertModules[0].Disabled != false || cfg.CertModules[1].Disabled != false ||
		cfg.CertModules[2].Disabled != true {
		t.Error("Wrong disabled value")
	}

	if cfg.CertModules[0].SkipValidation != true || cfg.CertModules[1].SkipValidation != false ||
		cfg.CertModules[2].SkipValidation != false {
		t.Error("Wrong skip validation value")
	}

	if !reflect.DeepEqual(cfg.CertModules[0].ExtendedKeyUsage, []string{"clientAuth"}) ||
		!reflect.DeepEqual(cfg.CertModules[1].ExtendedKeyUsage, []string{"serverAuth"}) ||
		!reflect.DeepEqual(cfg.CertModules[2].ExtendedKeyUsage, []string{"clientAuth", "serverAuth"}) {
		t.Error("Wrong extended key usage value")
	}

	if !reflect.DeepEqual(cfg.CertModules[0].AlternativeNames, []string{"host1"}) ||
		!reflect.DeepEqual(cfg.CertModules[1].AlternativeNames, []string{"host2"}) ||
		!reflect.DeepEqual(cfg.CertModules[2].AlternativeNames, []string{"host3"}) {
		t.Error("Wrong alternative names value")
	}
}

func TestNewErrors(t *testing.T) {
	// Executing new statement with nonexisting config file
	if _, err := config.New("some_nonexisting_file"); err == nil {
		t.Errorf("No error was returned for nonexisting config")
	}

	configFile := path.Join(tmpDir, "bad_config.cfg")

	// Creating wrong config
	if err := saveConfigFile(configFile, "WRONG JSON FORMAT ]}"); err != nil {
		t.Errorf("Unable to create wrong config file. Err %s", err)
	}

	// Testing with wrong json format
	if _, err := config.New(configFile); err == nil {
		t.Errorf("No error was returned for config with wrong format")
	}
}

func TestIdentifier(t *testing.T) {
	if cfg.Identifier.Plugin != "testIdentifier" {
		t.Errorf("Wrong identifier plugin: %s", cfg.Identifier.Plugin)
	}

	var moduleConfig struct {
		Param1 string `json:"param1"`
		Param2 string `json:"param2"`
	}

	if err := json.Unmarshal(cfg.Identifier.Params, &moduleConfig); err != nil {
		t.Errorf("Can't unmarshal module config: %s", err)
	}

	if moduleConfig.Param1 != "Value1" || moduleConfig.Param2 != "Value2" {
		t.Error("Invalid module config parm value")
	}
}

func TestFinishProvisioningCmdArgs(t *testing.T) {
	if !reflect.DeepEqual(cfg.FinishProvisioningCmdArgs, []string{"/var/aos/finish.sh"}) {
		t.Errorf("Wrong finish provisioning cmd args: %v", cfg.FinishProvisioningCmdArgs)
	}
}

func TestDiskEncryptionCmdArgs(t *testing.T) {
	if !reflect.DeepEqual(cfg.DiskEncryptionCmdArgs, []string{"/bin/sh", "/var/aos/encrypt.sh"}) {
		t.Errorf("Wrong disk encryption cmd args: %v", cfg.DiskEncryptionCmdArgs)
	}
}

func TestEnablePermissionsHandler(t *testing.T) {
	if !cfg.EnablePermissionsHandler {
		t.Errorf("Wrong enable permissions handler value: %v", cfg.EnablePermissionsHandler)
	}
}

func TestNodeID(t *testing.T) {
	if cfg.NodeID != "NodeID" {
		t.Errorf("Wrong node ID parameters: %s", cfg.NodeID)
	}
}

func TestNodeType(t *testing.T) {
	if cfg.NodeType != "NodeType" {
		t.Errorf("Wrong node type parameters: %s", cfg.NodeType)
	}
}

func TestRemoteIAMs(t *testing.T) {
	if !reflect.DeepEqual(cfg.RemoteIAMs, []config.RemoteIAM{
		{NodeID: "Node1", URL: "remotehost1:8089"},
		{NodeID: "Node2", URL: "remotehost2:8089"},
	}) {
		t.Errorf("Wrong connected IAM's parameters: %v", cfg.RemoteIAMs)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func saveConfigFile(fileName string, configContent string) (err error) {
	if err = os.WriteFile(fileName, []byte(configContent), 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = os.MkdirTemp("", "iam_"); err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	configContent := `{
		"IAMPublicServerUrl": "localhost:8090",
		"IAMProtectedServerUrl": "localhost:8089",
		"CACert": "/etc/ssl/certs/rootCA.crt",
		"CertStorage": "/var/aos/crypt/iam/",
		"NodeId": "NodeID",
		"NodeType": "NodeType",
		"WorkingDir": "/var/aos/iamanager",
		"FinishProvisioningCmdArgs": [
			"/var/aos/finish.sh"
		],
		"DiskEncryptionCmdArgs": [
			"/bin/sh",
			"/var/aos/encrypt.sh"
		],
		"EnablePermissionsHandler": true,
		"RemoteIams": [
			{
				"nodeId": "Node1",
				"url": "remotehost1:8089",
				"certIds": ["cert1", "cert2", "cert3"]
			},
			{
				"nodeId": "Node2",
				"url": "remotehost2:8089",
				"certIds": ["cert4", "cert5", "cert6"]
			}
		],
		"CertModules":[{
			"ID": "id1",
			"Plugin": "test1",
			"Algorithm": "rsa",
			"MaxItems": 1,
			"ExtendedKeyUsage": ["clientAuth"],
			"AlternativeNames": ["host1"],
			"SkipValidation": true,
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}, {
			"ID": "id2",
			"Plugin": "test2",
			"Algorithm": "ecc",
			"MaxItems": 2,
			"ExtendedKeyUsage": ["serverAuth"],
			"AlternativeNames": ["host2"],
			"SkipValidation": false,
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}, {
			"ID": "id3",
			"Plugin": "test3",
			"Algorithm": "rsa",
			"MaxItems": 3,
			"ExtendedKeyUsage": ["clientAuth", "serverAuth"],
			"AlternativeNames": ["host3"],
			"Disabled": true,
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}],
		"Identifier": {
			"Plugin": "testIdentifier",
			"Params": {
				"Param1": "Value1",
				"Param2": "Value2"
			}
		}
	}`

	configFile := path.Join(tmpDir, "aos_iamanager.cfg")

	if err = saveConfigFile(configFile, configContent); err != nil {
		return aoserrors.Wrap(err)
	}

	if cfg, err = config.New(configFile); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func cleanup() (err error) {
	if err := os.RemoveAll(tmpDir); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}
