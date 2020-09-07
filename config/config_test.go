// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Renesas Inc.
// Copyright 2019 EPAM Systems Inc.
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
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"

	"aos_certificatemanager/config"
)

/*******************************************************************************
 * Vars
 ******************************************************************************/

var cfg *config.Config
var tmpDir string

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
	if cfg.ServerURL != "localhost:8090" {
		t.Errorf("Wrong ServerURL value: %s", cfg.ServerURL)
	}

	if cfg.Cert != "cert.pem" {
		t.Errorf("Wrong cert value: %s", cfg.Cert)
	}

	if cfg.Key != "key.pem" {
		t.Errorf("Wrong key value: %s", cfg.Key)
	}
}

func TestGetWorkingDir(t *testing.T) {
	if cfg.WorkingDir != "/var/aos/certificatemanager" {
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

	if cfg.CertModules[0].Plugin != "test1" || cfg.CertModules[1].Plugin != "test2" || cfg.CertModules[2].Plugin != "test3" {
		t.Error("Wrong plugin value")
	}

	if cfg.CertModules[0].Disabled != false || cfg.CertModules[1].Disabled != false || cfg.CertModules[2].Disabled != true {
		t.Error("Disabled value")
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

/*******************************************************************************
 * Private
 ******************************************************************************/

func saveConfigFile(fileName string, configContent string) (err error) {
	if err = ioutil.WriteFile(fileName, []byte(configContent), 0644); err != nil {
		return err
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = ioutil.TempDir("", "cm_"); err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	configContent := `{
		"ServerUrl": "localhost:8090",
		"Cert": "cert.pem",
		"Key": "key.pem",	
		"WorkingDir": "/var/aos/certificatemanager",
		"CertModules":[{
			"ID": "id1",
			"Plugin": "test1",
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}, {
			"ID": "id2",
			"Plugin": "test2",
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}, {
			"ID": "id3",
			"Plugin": "test3",
			"Disabled": true,
			"Params": {
				"Param1" :"value1",
				"Param2" : 2
			}
		}]
	}`

	configFile := path.Join(tmpDir, "aos_certificatemanager.cfg")

	if err = saveConfigFile(configFile, configContent); err != nil {
		return err
	}

	if cfg, err = config.New(configFile); err != nil {
		return err
	}

	return nil
}

func cleanup() (err error) {
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}

	return nil
}
