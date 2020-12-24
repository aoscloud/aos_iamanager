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

package certhandler_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
	"aos_iamanager/config"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type moduleData struct {
	csr      string
	certURL  string
	password string
}

type testModule struct {
	data *moduleData
}

type certDesc struct {
	certType string
	certInfo certhandler.CertInfo
}

type testStorage struct {
	certs []certDesc
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var tmpDir string

var cfg config.Config

var modules map[string]*testModule

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	var err error

	tmpDir, err = ioutil.TempDir("", "iam_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	cfg = config.Config{
		CertModules: []config.ModuleConfig{
			{ID: "cert1", Plugin: "testmodule"},
			{ID: "cert2", Plugin: "testmodule"},
			{ID: "cert3", Plugin: "testmodule"}}}

	modules = make(map[string]*testModule)

	certhandler.RegisterPlugin("testmodule", func(certType string, configJSON json.RawMessage,
		storage certhandler.CertStorage) (module certhandler.CertModule, err error) {
		certModule := &testModule{data: &moduleData{}}

		modules[certType] = certModule

		return certModule, nil
	})

	ret := m.Run()

	if err := os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing tmp dir: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestSetOwner(t *testing.T) {
	handler, err := certhandler.New(&cfg, &testStorage{})
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	password := "password"

	if err = handler.SetOwner("cert1", password); err != nil {
		t.Fatalf("Can't set owner: %s", err)
	}

	if modules["cert1"].data.password != password {
		t.Errorf("Wrong password: %s", modules["cert1"].data.password)
	}

	if err = handler.Clear("cert1"); err != nil {
		t.Fatalf("Can't clear: %s", err)
	}

	if modules["cert1"].data.password != "" {
		t.Errorf("Wrong password: %s", modules["cert1"].data.password)
	}
}

func TestCreateKeys(t *testing.T) {
	storage := &testStorage{}

	handler, err := certhandler.New(&cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	modules["cert1"].data.csr = "this is csr"

	csr, err := handler.CreateKeys("cert1", "systemID", "password")
	if err != nil {
		t.Fatalf("Can't create keys: %s", err)
	}

	if modules["cert1"].data.csr != csr {
		t.Errorf("Wrong CSR value: %s", string(csr))
	}
}

func TestApplyCertificate(t *testing.T) {
	storage := &testStorage{}

	handler, err := certhandler.New(&cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	modules["cert2"].data.certURL = "certURL"

	certURL, err := handler.ApplyCertificate("cert2", "this is certificate")
	if err != nil {
		t.Fatalf("Can't apply certificate: %s", err)
	}

	if modules["cert2"].data.certURL != certURL {
		t.Errorf("Wrong cert URL: %s", certURL)
	}
}

func TestGetCertificate(t *testing.T) {
	storage := &testStorage{}

	storage.AddCertificate("cert1", certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "1", "certURL1", "keyURL1", time.Now()})
	storage.AddCertificate("cert1", certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "2", "certURL2", "keyURL2", time.Now()})
	storage.AddCertificate("cert1", certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "3", "certURL3", "keyURL3", time.Now()})

	handler, err := certhandler.New(&cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	certURL, keyURL, err := handler.GetCertificate("cert1", []byte("issuer"), "2")
	if err != nil {
		t.Fatalf("Can't get certificate: %s", err)
	}

	if certURL != "certURL2" {
		t.Errorf("Wrong cert URL: %s", certURL)
	}

	if keyURL != "keyURL2" {
		t.Errorf("Wrong key URL: %s", keyURL)
	}

	if certURL, keyURL, err = handler.GetCertificate("cert1", nil, ""); err != nil {
		t.Fatalf("Can't get certificate: %s", err)
	}

	if certURL != "certURL1" {
		t.Errorf("Wrong cert URL: %s", certURL)
	}

	if keyURL != "keyURL1" {
		t.Errorf("Wrong key URL: %s", keyURL)
	}
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

func (module *testModule) SyncStorage() (err error) {
	return nil
}

func (module *testModule) SetOwner(password string) (err error) {
	module.data.password = password

	return nil
}

func (module *testModule) Clear() (err error) {
	module.data.password = ""

	return nil
}

func (module *testModule) CreateKeys(systemID, password string) (csr string, err error) {
	return module.data.csr, nil
}

func (module *testModule) ApplyCertificate(cert string) (certURL, keyURL string, err error) {
	return module.data.certURL, "", nil
}

func (module *testModule) Close() (err error) {
	return nil
}

func (storage *testStorage) AddCertificate(certType string, cert certhandler.CertInfo) (err error) {
	for _, item := range storage.certs {
		if item.certInfo.Issuer == cert.Issuer && item.certInfo.Serial == cert.Serial {
			return errors.New("certificate already exists")
		}
	}

	storage.certs = append(storage.certs, certDesc{certType, cert})

	return nil
}

func (storage *testStorage) GetCertificate(issuer, serial string) (cert certhandler.CertInfo, err error) {
	for _, item := range storage.certs {
		if item.certInfo.Issuer == issuer && item.certInfo.Serial == serial {
			return item.certInfo, nil
		}
	}

	return cert, errors.New("certificate not found")
}

func (storage *testStorage) GetCertificates(certType string) (certs []certhandler.CertInfo, err error) {
	for _, item := range storage.certs {
		if item.certType == certType {
			certs = append(certs, item.certInfo)
		}
	}

	return certs, nil
}

func (storage *testStorage) RemoveCertificate(certType, certURL string) (err error) {
	for i, item := range storage.certs {
		if item.certType == certType && item.certInfo.CertURL == certURL {
			storage.certs = append(storage.certs[:i], storage.certs[i+1:]...)

			return nil
		}
	}

	return errors.New("certificate not found")
}

func (storage *testStorage) RemoveAllCertificates(certType string) (err error) {
	newCerts := make([]certDesc, 0)

	for _, item := range storage.certs {
		if item.certType != certType {
			newCerts = append(newCerts, item)
		}
	}

	storage.certs = newCerts

	return nil
}
