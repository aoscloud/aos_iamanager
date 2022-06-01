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

package certhandler_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/testtools"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/certhandler"
	"github.com/aoscloud/aos_iamanager/config"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type moduleData struct {
	key        crypto.PrivateKey
	certInfo   certhandler.CertInfo
	removeCert string
	removeKey  string
	password   string
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

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var tmpDir string

var modules map[string]*testModule

var moduleValidInfos []certhandler.CertInfo

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func TestMain(m *testing.M) {
	var err error

	tmpDir, err = ioutil.TempDir("", "iam_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	modules = make(map[string]*testModule)

	certhandler.RegisterPlugin("testmodule", func(certType string,
		configJSON json.RawMessage,
	) (module certhandler.CertModule, err error) {
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

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestGetCertTypes(t *testing.T) {
	cfg := config.Config{
		CertModules: []config.ModuleConfig{
			{ID: "cert1", Plugin: "testmodule"},
			{ID: "cert2", Plugin: "testmodule"},
			{ID: "cert3", Plugin: "testmodule"},
		},
	}

	handler, err := certhandler.New("testID", &cfg, &testStorage{})
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	refCertTypes := make([]string, 0, len(cfg.CertModules))

	for _, module := range cfg.CertModules {
		refCertTypes = append(refCertTypes, module.ID)
	}

	getCertTypes := handler.GetCertTypes()

	sort.Strings(refCertTypes)
	sort.Strings(getCertTypes)

	if !reflect.DeepEqual(refCertTypes, getCertTypes) {
		t.Errorf("Wrong cert types: %v", getCertTypes)
	}
}

func TestSetOwner(t *testing.T) {
	cfg := config.Config{CertModules: []config.ModuleConfig{{ID: "cert1", Plugin: "testmodule"}}}

	handler, err := certhandler.New("testID", &cfg, &testStorage{})
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

func TestCreateKey(t *testing.T) {
	cfg := config.Config{CertModules: []config.ModuleConfig{
		{
			ID:               "cert1",
			Plugin:           "testmodule",
			ExtendedKeyUsage: []string{"serverAuth", "clientAuth"},
			AlternativeNames: []string{"name1", "name2"},
		},
	}}

	handler, err := certhandler.New("testID", &cfg, &testStorage{})
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	csrData, err := handler.CreateKey("cert1", "password")
	if err != nil {
		t.Fatalf("Can't create key: %s", err)
	}

	// Get key public part

	signer, ok := modules["cert1"].data.key.(crypto.Signer)
	if !ok {
		t.Fatalf("Wrong key type")
	}

	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("Can't marshal public key: %s", err)
	}

	// Check CSR

	block, _ := pem.Decode(csrData)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Can't parse certificate request: %s", err)
	}

	if !reflect.DeepEqual(csr.DNSNames, []string{"name1", "name2"}) {
		t.Errorf("Wrong CSR DNS names: %v", csr.DNSNames)
	}

	extendedKeyUsageValue, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	})
	if err != nil {
		t.Fatalf("Can't marshal extended key usage: %s", err)
	}

	extendedKeyUsage := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: extendedKeyUsageValue}

	if len(csr.Extensions) < 2 {
		t.Fatalf("Wrong CSR extension length: %d", len(csr.Extensions))
	}

	if !reflect.DeepEqual(csr.Extensions[1], extendedKeyUsage) {
		t.Errorf("Wrong CSR extended key usage: %v", csr.Extensions[1])
	}

	pubCSR, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("Can't marshal public key: %s", err)
	}

	if !bytes.Equal(keyPub, pubCSR) {
		t.Error("Public key mismatch")
	}
}

func TestApplyCertificate(t *testing.T) {
	cfg := config.Config{CertModules: []config.ModuleConfig{{ID: "cert1", Plugin: "testmodule"}}}

	handler, err := certhandler.New("testID", &cfg, &testStorage{})
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	modules["cert1"].data.certInfo = certhandler.CertInfo{
		CertURL: "certURL",
		KeyURL:  "keyURL",
	}

	certURL, err := handler.ApplyCertificate("cert1", testtools.GetCACertificate())
	if err != nil {
		t.Fatalf("Can't apply certificate: %s", err)
	}

	if modules["cert1"].data.certInfo.CertURL != certURL {
		t.Errorf("Wrong cert URL: %s", certURL)
	}
}

func TestGetCertificate(t *testing.T) {
	storage := &testStorage{}

	cfg := config.Config{CertModules: []config.ModuleConfig{{ID: "cert1", Plugin: "testmodule"}}}

	handler, err := certhandler.New("testID", &cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "1", "certURL1", "keyURL1", time.Now()})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "2", "certURL2", "keyURL2", time.Now()})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{base64.StdEncoding.EncodeToString([]byte("issuer")), "3", "certURL3", "keyURL3", time.Now()})

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

func TestMaxItems(t *testing.T) {
	maxItems := 5
	addItems := 10

	cfg := config.Config{CertModules: []config.ModuleConfig{{ID: "cert1", Plugin: "testmodule", MaxItems: maxItems}}}

	storage := &testStorage{}

	handler, err := certhandler.New("testID", &cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	for i := 0; i < addItems; i++ {
		modules["cert1"].data.certInfo = certhandler.CertInfo{
			CertURL:  fmt.Sprintf("certURL%d", i),
			KeyURL:   fmt.Sprintf("keyURL%d", i),
			Serial:   fmt.Sprintf("Serial%d", i),
			Issuer:   fmt.Sprintf("Issuer%d", i),
			NotAfter: time.Now(),
		}

		if _, err = handler.ApplyCertificate("cert1", testtools.GetCACertificate()); err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}

		if i >= maxItems {
			if modules["cert1"].data.removeCert != fmt.Sprintf("certURL%d", i-maxItems) {
				t.Errorf("Delete unexpected certificate: %s", modules["cert1"].data.removeCert)
			}

			if modules["cert1"].data.removeKey != fmt.Sprintf("keyURL%d", i-maxItems) {
				t.Errorf("Delete unexpected certificate: %s", modules["cert1"].data.removeKey)
			}
		}
	}

	certs, err := storage.GetCertificates("cert1")
	if err != nil {
		t.Fatalf("Can't get certificates: %s", err)
	}

	for i, cert := range certs {
		if cert.CertURL != fmt.Sprintf("certURL%d", maxItems+i) {
			t.Errorf("Unexpected certificate found: %s", cert.CertURL)
		}
	}
}

func TestSyncStorage(t *testing.T) {
	storage := &testStorage{}

	moduleValidInfos = []certhandler.CertInfo{
		{Issuer: "issuer3", Serial: "serial3", CertURL: "cert3", KeyURL: "key3"},
		{Issuer: "issuer4", Serial: "serial4", CertURL: "cert4", KeyURL: "key4"},
		{Issuer: "issuer5", Serial: "serial5", CertURL: "cert5", KeyURL: "key5"},
		{Issuer: "issuer6", Serial: "serial6", CertURL: "cert6", KeyURL: "key6"},
		{Issuer: "issuer7", Serial: "serial7", CertURL: "cert7", KeyURL: "key7"},
	}

	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{Issuer: "issuer1", Serial: "serial1", CertURL: "cert1", KeyURL: "key1"})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{Issuer: "issuer2", Serial: "serial2", CertURL: "cert2", KeyURL: "key2"})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{Issuer: "issuer3", Serial: "serial3", CertURL: "cert3", KeyURL: "key3"})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{Issuer: "issuer4", Serial: "serial4", CertURL: "cert4", KeyURL: "key4"})
	_ = storage.AddCertificate("cert1",
		certhandler.CertInfo{Issuer: "issuer5", Serial: "serial5", CertURL: "cert5", KeyURL: "key5"})

	cfg := config.Config{CertModules: []config.ModuleConfig{{ID: "cert1", Plugin: "testmodule"}}}

	handler, err := certhandler.New("testID", &cfg, storage)
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	certInfos, err := storage.GetCertificates("cert1")
	if err != nil {
		t.Fatalf("Can't get certificates: %s", err)
	}

	if !reflect.DeepEqual(moduleValidInfos, certInfos) {
		t.Error("Wrong storage items")
	}
}

func TestCreateSelfSignedCert(t *testing.T) {
	cfg := config.Config{CertModules: []config.ModuleConfig{
		{ID: "cert1", Plugin: "testmodule"},
	}}

	handler, err := certhandler.New("testID", &cfg, &testStorage{})
	if err != nil {
		t.Fatalf("Can't create cert handler: %s", err)
	}
	defer handler.Close()

	err = handler.CreateSelfSignedCert("cert1", "password")
	if err != nil {
		t.Fatalf("Can't create create selfsigned cert: %s", err)
	}

	// Get key public part

	signer, ok := modules["cert1"].data.key.(crypto.Signer)
	if !ok {
		t.Fatalf("Wrong key type")
	}

	_, err = x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("Can't marshal public key: %s", err)
	}
}

/***********************************************************************************************************************
 * Interfaces
 **********************************************************************************************************************/

func (module *testModule) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error,
) {
	return moduleValidInfos, nil, nil, nil
}

func (module *testModule) SetOwner(password string) (err error) {
	module.data.password = password

	return nil
}

func (module *testModule) Clear() (err error) {
	module.data.password = ""

	return nil
}

func (module *testModule) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	if module.data.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return module.data.key, nil
}

func (module *testModule) ApplyCertificate(
	certs []*x509.Certificate,
) (certInfo certhandler.CertInfo, password string, err error) {
	return module.data.certInfo, "", nil
}

func (module *testModule) RemoveCertificate(certURL, password string) (err error) {
	module.data.removeCert = certURL

	return nil
}

func (module *testModule) RemoveKey(keyURL, password string) (err error) {
	module.data.removeKey = keyURL

	return nil
}

func (module *testModule) Close() (err error) {
	return nil
}

func (storage *testStorage) AddCertificate(certType string, cert certhandler.CertInfo) (err error) {
	for _, item := range storage.certs {
		if item.certInfo.Issuer == cert.Issuer && item.certInfo.Serial == cert.Serial {
			return aoserrors.New("certificate already exists")
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

	return cert, aoserrors.New("certificate not found")
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

	return aoserrors.New("certificate not found")
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
