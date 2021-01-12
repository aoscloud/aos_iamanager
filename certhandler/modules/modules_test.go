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

package certmodules_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
	"aos_iamanager/certhandler/modules/swmodule"
	"aos_iamanager/certhandler/modules/tpmmodule"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type certDesc struct {
	certType string
	certInfo certhandler.CertInfo
}

type testStorage struct {
	certs []certDesc
}

type createModuleType func(storagePath string, maxItem int,
	storage certhandler.CertStorage, doReset bool) (module certhandler.CertModule, err error)

/*******************************************************************************
 * Var
 ******************************************************************************/

var tmpDir string

var tpmSimulator *simulator.Simulator

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

	tmpDir, err = ioutil.TempDir("", "um_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	if tpmSimulator, err = simulator.Get(); err != nil {
		log.Fatalf("Can't get TPM simulator: %s", err)
	}

	ret := m.Run()

	tpmSimulator.Close()

	if err := os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing temporary dir: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestUpdateCertificate(t *testing.T) {
	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		storage := &testStorage{}

		certStorage := path.Join(tmpDir, "certStorage")

		module, err := createModule(certStorage, 1, storage, true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}
		defer module.Close()

		// Set owner

		password := "password"

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		// Create keys

		csr, err := module.CreateKeys("testsystem", password)
		if err != nil {
			t.Fatalf("Can't create keys: %s", err)
		}

		// Verify CSR

		csrFile := path.Join(tmpDir, "data.csr")

		if err = ioutil.WriteFile(csrFile, []byte(csr), 0644); err != nil {
			t.Fatalf("Can't write CSR to file: %s", err)
		}

		out, err := exec.Command("openssl", "req", "-text", "-noout", "-verify", "-inform", "PEM", "-in", csrFile).CombinedOutput()
		if err != nil {
			t.Fatalf("Can't verify CSR: %s, %s", out, err)
		}

		// Apply certificate

		cert, err := generateCertificate(csr)
		if err != nil {
			t.Fatalf("Can't generate certificate: %s", err)
		}

		certURL, keyURL, err := module.ApplyCertificate(cert)
		if err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}

		// Get certificate

		block, _ := pem.Decode([]byte(cert))

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Can't parse certificate: %s", err)
		}

		certInfo, err := storage.GetCertificate(base64.StdEncoding.EncodeToString(x509Cert.RawIssuer), fmt.Sprintf("%X", x509Cert.SerialNumber))
		if err != nil {
			t.Fatalf("Can't get certificate: %s", err)
		}

		if certURL != certInfo.CertURL || keyURL != certInfo.KeyURL {
			t.Errorf("Wrong certificate or key URL: %s, %s", certInfo.CertURL, certInfo.KeyURL)
		}

		// Check encrypt/decrypt with private key

		keyVal, err := url.Parse(keyURL)
		if err != nil {
			t.Fatalf("Wrong key URL: %s", keyURL)
		}

		originMessage := []byte("This is origin message")
		var decryptedData []byte

		switch keyVal.Scheme {
		case "file":
			key, err := getKey(keyVal.Path)
			if err != nil {
				t.Fatalf("Can't get key: %s", err)
			}

			encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, originMessage)
			if err != nil {
				t.Errorf("Can't encrypt message: %s", err)
			}

			if decryptedData, err = rsa.DecryptPKCS1v15(rand.Reader, key, encryptedData); err != nil {
				t.Errorf("Can't decrypt message: %s", err)
			}

		case "tpm":
			handle, err := strconv.ParseUint(keyVal.Hostname(), 0, 32)
			if err != nil {
				t.Fatalf("Can't parse key URL: %s", err)
			}

			originMessage := []byte("This is origin message")

			encryptedData, err := tpm2.RSAEncrypt(tpmSimulator, tpmutil.Handle(handle), originMessage, &tpm2.AsymScheme{Alg: tpm2.AlgRSAES}, "")
			if err != nil {
				t.Errorf("Can't encrypt message: %s", err)
			}

			if decryptedData, err = tpm2.RSADecrypt(tpmSimulator, tpmutil.Handle(handle), "", encryptedData, &tpm2.AsymScheme{Alg: tpm2.AlgRSAES}, ""); err != nil {
				t.Errorf("Can't decrypt message: %s", err)
			}

		default:
			t.Fatalf("Unsupported key scheme: %s", keyVal.Scheme)
		}

		if !bytes.Equal(originMessage, decryptedData) {
			t.Error("Decrypt error")
		}
	}
}

func TestMaxItems(t *testing.T) {
	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		storage := &testStorage{}
		certStorage := path.Join(tmpDir, "certStorage")

		module, err := createModule(certStorage, 1, storage, true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}
		defer module.Close()

		// Set owner

		password := "password"

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		for i := 0; i < 3; i++ {

			// Create keys

			csr, err := module.CreateKeys("testsystem", password)
			if err != nil {
				t.Fatalf("Can't create keys: %s", err)
			}

			// Apply certificate

			cert, err := generateCertificate(csr)
			if err != nil {
				t.Fatalf("Can't generate certificate: %s", err)
			}

			certURL, keyURL, err := module.ApplyCertificate(cert)
			if err != nil {
				t.Fatalf("Can't apply certificate: %s", err)
			}

			// Check key files

			keyVal, err := url.Parse(keyURL)
			if err != nil {
				t.Fatalf("Wrong key URL: %s", keyURL)
			}

			switch keyVal.Scheme {
			case "file":
				keyFiles, err := getKeyFiles(certStorage)
				if err != nil {
					t.Fatalf("Can't get key files")
				}

				if len(keyFiles) != 1 {
					t.Errorf("Wrong key files count: %d", len(keyFiles))
				}

				if err = checkFileURL(keyURL, keyFiles[0]); err != nil {
					t.Errorf("Check key URL error: %s", err)
				}

			case "tpm":
				handles, err := getPersistentHandles()
				if err != nil {
					t.Fatalf("Can't get peristent handles")
				}

				if len(handles) != 1 {
					t.Errorf("Wrong persistent handles count: %d", len(handles))
				}

				if err = checkHandleURL(keyURL, handles[0]); err != nil {
					t.Errorf("Check key URL error: %s", err)
				}

			default:
				t.Fatalf("Unsupported key scheme: %s", keyVal.Scheme)
			}

			// Check cert files

			certFiles, err := getCertFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get cert files")
			}

			if len(certFiles) != 1 {
				t.Errorf("Wrong cert files count: %d", len(certFiles))
			}

			if err = checkFileURL(certURL, certFiles[0]); err != nil {
				t.Errorf("Check cert URL error: %s", err)
			}
		}
	}
}

func TestSyncStorage(t *testing.T) {
	// Test items:
	// * valid     - cert file, handle, DB entry
	// * wrongDB   - DB entry but no cert file
	// * wrongFile - no DB entry and no handle
	// If cert file has DB entry but no handle - not considered

	testData := []string{"valid", "wrongDB", "wrongFile", "validFile", "valid", "wrongSerial", "wrongIssuer", "valid"}

	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		var goodItems []certhandler.CertInfo

		storage := &testStorage{}

		certStorage := path.Join(tmpDir, "certStorage")

		module, err := createModule(certStorage, len(testData), storage, true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}

		// Set owner

		password := "password"

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		for _, item := range testData {
			// Create keys

			csr, err := module.CreateKeys("testsystem", password)
			if err != nil {
				t.Fatalf("Can't create keys: %s", err)
			}

			// Apply certificate

			cert, err := generateCertificate(csr)
			if err != nil {
				t.Fatalf("Can't generate certificate: %s", err)
			}

			certURL, keyURL, err := module.ApplyCertificate(cert)
			if err != nil {
				t.Fatalf("Can't apply certificate: %s", err)
			}

			certVal, err := url.Parse(certURL)
			if err != nil {
				t.Fatalf("Can't parse cert URL: %s", err)
			}

			keyVal, err := url.Parse(keyURL)
			if err != nil {
				t.Fatalf("Can't parse key URL: %s", err)
			}

			block, _ := pem.Decode([]byte(cert))

			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Can't parse certificate: %s", err)
			}

			switch item {
			case "wrongDB":
				if err = os.Remove(certVal.Path); err != nil {
					t.Errorf("Can't remove cert file: %s", err)
				}

			case "wrongFile":
				if err = storage.RemoveCertificate("test", certURL); err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				switch keyVal.Scheme {
				case "file":
					if err = os.Remove(keyVal.Path); err != nil {
						t.Errorf("Can't remove key file: %s", err)
					}

				case "tpm":
					handle, err := strconv.ParseUint(keyVal.Hostname(), 0, 32)
					if err != nil {
						t.Errorf("Can't parse key handle: %s", err)
					}

					if err = tpm2.EvictControl(tpmSimulator, password, tpm2.HandleOwner, tpmutil.Handle(handle),
						tpmutil.Handle(handle)); err != nil {
						t.Errorf("Can't remove key handle: %s", err)
					}

				default:
					t.Errorf("Unsupported key scheme: %s", keyVal.Scheme)
				}

			case "wrongSerial":
				certInfo, err := storage.GetCertificate(base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
					fmt.Sprintf("%X", x509Cert.SerialNumber))
				if err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				if err = storage.RemoveCertificate("test", certURL); err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				certInfo.Serial = "invalid serial"

				if err = storage.AddCertificate("test", certInfo); err != nil {
					t.Errorf("Can't add cert: %s", err)
				}

				goodItems = append(goodItems, certhandler.CertInfo{CertURL: certURL, KeyURL: keyURL})

			case "wrongIssuer":
				certInfo, err := storage.GetCertificate(base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
					fmt.Sprintf("%X", x509Cert.SerialNumber))
				if err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				if err = storage.RemoveCertificate("test", certURL); err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				certInfo.Issuer = "wrong issuer"

				if err = storage.AddCertificate("test", certInfo); err != nil {
					t.Errorf("Can't add cert: %s", err)
				}

				goodItems = append(goodItems, certhandler.CertInfo{CertURL: certURL, KeyURL: keyURL})

			case "validFile":
				if err = storage.RemoveCertificate("test", certURL); err != nil {
					t.Errorf("Can't remove cert entry: %s", err)
				}

				goodItems = append(goodItems, certhandler.CertInfo{CertURL: certURL, KeyURL: keyURL})

			default:
				goodItems = append(goodItems, certhandler.CertInfo{CertURL: certURL, KeyURL: keyURL})
			}
		}

		module.Close()

		if module, err = createModule(certStorage, 1, storage, false); err != nil {
			t.Fatalf("Can't create module: %s", err)
		}
		defer module.Close()

		if err = module.SyncStorage(); err != nil {
			t.Fatalf("Can't sync storage: %s", err)
		}

		certInfos, err := storage.GetCertificates("test")
		if err != nil {
			t.Fatalf("Can't get certificates: %s", err)
		}

		for _, goodItem := range goodItems {
			found := false

			infoIndex := 0

			for i, info := range certInfos {
				if info.CertURL == goodItem.CertURL && info.KeyURL == goodItem.KeyURL {
					found = true
					infoIndex = i
				}
			}

			if !found {
				t.Errorf("Expected item not found in storage, certURL: %s, keyURL: %s", goodItem.CertURL, goodItem.KeyURL)
			} else {
				certInfos = append(certInfos[:infoIndex], certInfos[infoIndex+1:]...)
			}
		}

		for _, badItem := range certInfos {
			t.Errorf("Item should not be in srorage, certURL: %s, keyURL: %s", badItem.CertURL, badItem.KeyURL)
		}
	}
}

func TestSetOwnerClear(t *testing.T) {
	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		storage := &testStorage{}
		certStorage := path.Join(tmpDir, "certStorage")

		module, err := createModule(certStorage, 1, storage, true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}
		defer module.Close()

		// Set owner

		password := "password"

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		// Check if we can set owner twice
		if err = module.SetOwner(password); err != nil {
			t.Errorf("Can't set owner: %s", err)
		}

		// Create keys

		csr, err := module.CreateKeys("testsystem", password)
		if err != nil {
			t.Fatalf("Can't create keys: %s", err)
		}

		// Apply certificate

		cert, err := generateCertificate(csr)
		if err != nil {
			t.Fatalf("Can't generate certificate: %s", err)
		}

		_, keyURL, err := module.ApplyCertificate(cert)
		if err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}

		// Check key files

		keyVal, err := url.Parse(keyURL)
		if err != nil {
			t.Fatalf("Wrong key URL: %s", keyURL)
		}

		switch keyVal.Scheme {
		case "file":
			// Check key files

			keyFiles, err := getKeyFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get key files")
			}

			if len(keyFiles) != 1 {
				t.Errorf("Wrong key files count: %d", len(keyFiles))
			}

			certFiles, err := getCertFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get cert files")
			}

			if len(certFiles) != 1 {
				t.Errorf("Wrong cert files count: %d", len(certFiles))
			}

			if len(storage.certs) != 1 {
				t.Errorf("Wrong storage entries count: %d", len(storage.certs))
			}

		case "tpm":
			handles, err := getPersistentHandles()
			if err != nil {
				t.Fatalf("Can't get persistent handles: %s", err)
			}

			if len(handles) != 1 {
				t.Errorf("Wrong handles count: %d", len(handles))
			}

			certFiles, err := getCertFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get cert files")
			}

			if len(certFiles) != 1 {
				t.Errorf("Wrong cert files count: %d", len(certFiles))
			}

			if len(storage.certs) != 1 {
				t.Errorf("Wrong storage entries count: %d", len(storage.certs))
			}

		default:
			t.Errorf("Unsupported key scheme: %s", keyVal.Scheme)

			continue
		}

		// Clear

		if err = module.Clear(); err != nil {
			t.Fatalf("Can't clear: %s", err)
		}

		switch keyVal.Scheme {
		case "file":
			// Check key files

			keyFiles, err := getKeyFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get key files")

			}

			if len(keyFiles) != 0 {
				t.Errorf("Wrong key files count: %d", len(keyFiles))
			}

			certFiles, err := getCertFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get cert files")
			}

			if len(certFiles) != 0 {
				t.Errorf("Wrong cert files count: %d", len(certFiles))
			}

			if len(storage.certs) != 0 {
				t.Errorf("Wrong storage entries count: %d", len(storage.certs))
			}
		case "tpm":
			handles, err := getPersistentHandles()
			if err != nil {
				t.Fatalf("Can't get persistent handles: %s", err)
			}

			if len(handles) != 0 {
				t.Errorf("Wrong handles count: %d", len(handles))
			}

			certFiles, err := getCertFiles(certStorage)
			if err != nil {
				t.Fatalf("Can't get cert files")
			}

			if len(certFiles) != 0 {
				t.Errorf("Wrong cert files count: %d", len(certFiles))
			}

		default:
			t.Errorf("Unsupported key scheme: %s", keyVal.Scheme)

			continue
		}
	}
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

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

/*******************************************************************************
 * Private
 ******************************************************************************/

func createSwModule(storagePath string, maxItem int,
	storage certhandler.CertStorage, doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(storagePath); err != nil {
			return nil, err
		}
	}

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s","maxItems":%d,
	  "ExtendedKeyUsage": ["serverAuth","clientAuth"],	"AlternativeNames" : ["aosserver"]}`, storagePath, maxItem))

	return swmodule.New("test", config, storage)
}

func createTpmModule(storagePath string, maxItem int,
	storage certhandler.CertStorage, doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(storagePath); err != nil {
			return nil, err
		}

		if err = tpmSimulator.ManufactureReset(); err != nil {
			return nil, err
		}
	}

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s","maxItems":%d}`, storagePath, maxItem))

	return tpmmodule.New("test", config, storage, tpmSimulator)
}

func generateCertificate(csr string) (cert string, err error) {
	caCert :=
		`-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIUefLO+XArcR2jeqrgGqQlTM20N/swDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCVUExEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcM
BEt5aXYxDTALBgNVBAoMBEVQQU0wHhcNMjAwNzAzMTU0NzEzWhcNMjAwODAyMTU0
NzEzWjBAMQswCQYDVQQGEwJVQTETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UE
BwwES3lpdjENMAsGA1UECgwERVBBTTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMQAdRAyH+S6QSCYAq09Kn5uhNgBSEcOwUTdTH1W9BSgXaHAbHQmY0py
2EnXoQ4/B+xdFsFLRpW7dvDaXcgMjjX1B/Yn52lF2OLdTaRwcA5/5wU2hAKAs4lu
lLRS1Ez48cRutjyVwzB70EB78Og/79SbZnrE73RhE4gUGq1/7l95VrQeVyMxXPSz
T5DVQrwZ/TnNDHbB2WDP3oWi4EhHRSE3GxO9OvVIlWtps2/VLLGDjFKDDw57c+CJ
GtYDDSQGSAzYgKHLbC4YZdatLCzLOK+HYMBMQ+A+h1FFDOQiafjc2hhNAJJgK4YE
S2bTKPSDwUFvNXlojLUuRqmeJblTfU8CAwEAAaNTMFEwHQYDVR0OBBYEFGTTfDCg
4dwM/qAGCsMIt3akp3kaMB8GA1UdIwQYMBaAFGTTfDCg4dwM/qAGCsMIt3akp3ka
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACE7Dm84YTAhxnjf
BC5tekchab1LtG00kGD3olYIrk60ST9CTkeZKbIRUiJguu7YyS8/9acCI5PrL+Bj
JeThNo8BiHgEJ0MZkUI9JhIqWT1dHFZoiIWBJia6IyEEFrUEfKBpYW85Get25em3
xokm39qQ2HFKJXbzixE/4F792lUWU49g4tvClrkRrVISBxy1xPAQZ38dep9NMhHe
puBh64yKH073veYqAlkv4p+m0VDJsSRhrhHnC1n37P6UIy3FhyxfsnQ4JTbDsjyH
d43D/UeLrvqwwJvRWqwa1XCbkxyhBQ+/2Soq/ym+EFTgJJcT/UjXZMU6C3NF7oLa
2bbVjCU=
-----END CERTIFICATE-----`

	caKey :=
		`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxAB1EDIf5LpBIJgCrT0qfm6E2AFIRw7BRN1MfVb0FKBdocBs
dCZjSnLYSdehDj8H7F0WwUtGlbt28NpdyAyONfUH9ifnaUXY4t1NpHBwDn/nBTaE
AoCziW6UtFLUTPjxxG62PJXDMHvQQHvw6D/v1JtmesTvdGETiBQarX/uX3lWtB5X
IzFc9LNPkNVCvBn9Oc0MdsHZYM/ehaLgSEdFITcbE7069UiVa2mzb9UssYOMUoMP
Dntz4Ika1gMNJAZIDNiAoctsLhhl1q0sLMs4r4dgwExD4D6HUUUM5CJp+NzaGE0A
kmArhgRLZtMo9IPBQW81eWiMtS5GqZ4luVN9TwIDAQABAoIBADsH0DnyfryKg/bn
EVdPpq6xZn0P1c7g2MB+zfyp5ZUYv1pp87//l8PiVtXWhYEe5qn/V00b+MQ705Sy
j7AiZ+pERAOU/RMtoCajdDDkVDtpthBR3OxMCsaHcW3lzF7qUxZQKb6RdFnz0EK7
kVDBgN/Ndc3f5iZs3k8LjwVWFFrYTzkM+5vD7W5u0ORwOPuvXvoR39fIbKAd2DcD
Q++lEt/+E1Uqggenpuyewgr/gg5OTIN9ky3bksjSnjqfb5ClmNypEp0oLV3aF/y+
B4GiZjckkWEFZX9gtqP+6TGb4IQVnSJz7k7n3vwOf5VUQjgZYx/363WdGalIUG79
NkGDwOECgYEA8hFX5Dy+Wiap43lc+P6MH1lxNKCwjMi5SvM/mYpi3vFIuHo8FxTW
HLKOqB82l/9N8WnC76JWq4raPyOKt+pyQKknSg3iArxks7fy4h/k+5F2c6/cFb6P
TaFDt7rG3B7x9gcJbNj2U0mMEn77vcYZ39DABv1yVQumOQA3wvcST9cCgYEAz0hf
Tbf/QILO4oQ/Olv9bN0oOVkwmm61RZyQHSykX3seTgNkkJ1EZRuqHPUIJGe0pc5/
jMQfK9WthYjx28YNnXlNCwWYf7M7n1rN2DsZciT0uQIio65GiDK4w3oRhTAWgX7L
QiH5eY6MxXMj68lHhTuFI/wSPeiksdFgtvnX70kCgYBUX30uHYoPrChNFFE2rKq0
hp1xxYykFZaYLD7/yn95y8oYGur09JtIt2gH65FA24kUW1PJ6OCivCwkE8RXJI2c
Qhlis4ISiA3lonkzHgDXOrV5z1M79QbH/Sy4To7fzJ1zrrI3UUxSbXE4RTCDzhfY
rk8wYIjIYd4XQh8tgqbMUwKBgQCcF5vtIsoNAnRZD82tXOiSulg4F3oKUaQgL642
yg9d95Dynot0e3mtyg9ojvz6rT3UPpS+pFH06IwrKt026wYFt/rUefpE7+vOLMsm
MhsPYdUIHRuItwxWNBv+2EWpTnUkPx9BReRgLYDEj9hVDtXU9uVkG8aA6Fhdr5Zt
M+fwQQKBgAbcuUeR9RseENAYl2fTf6ZaZ6pbK2HHo3qOqaY5vWpMESUOsAuC46qj
anwM76TcEbTBHgEWMDYiAYURXPVXisouoD6jsTcMDErwM/3kqMQ7rD6VM9uK7UF+
M0dV7SSA2lMvENr54k6V7zdaxnRDu8GL+OHtiZxeBG1P4pKhvf9l
-----END RSA PRIVATE KEY-----`

	csrConf :=
		`[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = AoS message-handler
O = EPAM
OU = AoS

[req_ext]
basicConstraints = CA:false
subjectKeyIdentifier=hash

[ext]
# PKIX recommendation.
basicConstraints = CA:false
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
#subjectAltName = @alt_names

[alt_names]
DNS.1 = *.westeurope.cloudapp.azure.com
DNS.2 = *.kyiv.epam.com
DNS.3 = *.minsk.epam.com
DNS.4 = *.aos-dev.test
DNS.5 = rabbitmq
DNS.6 = localhost
IP.1 = 127.0.0.1`

	caCertFile := path.Join(tmpDir, "ca.crt")
	caKeyFile := path.Join(tmpDir, "ca.key")
	csrFile := path.Join(tmpDir, "unit.csr")
	csrConfFile := path.Join(tmpDir, "csr.conf")
	unitCertFile := path.Join(tmpDir, "unit.der")

	if err = ioutil.WriteFile(csrFile, []byte(csr), 0644); err != nil {
		return "", err
	}

	if err = ioutil.WriteFile(caCertFile, []byte(caCert), 0644); err != nil {
		return "", err
	}

	if err = ioutil.WriteFile(caKeyFile, []byte(caKey), 0644); err != nil {
		return "", err
	}

	if err = ioutil.WriteFile(csrConfFile, []byte(csrConf), 0644); err != nil {
		return "", err
	}

	var out []byte

	if out, err = exec.Command("openssl", "req", "-inform", "PEM", "-in", csrFile, "-out", csrFile+".pem").CombinedOutput(); err != nil {
		return "", fmt.Errorf("message: %s, %s", string(out), err)
	}

	if out, err = exec.Command("openssl", "x509", "-req", "-in", csrFile+".pem",
		"-CA", caCertFile, "-CAkey", caKeyFile, "-extfile", csrConfFile, "-extensions", "ext",
		"-outform", "PEM", "-out", unitCertFile, "-CAcreateserial", "-days", "3650").CombinedOutput(); err != nil {
		return "", fmt.Errorf("message: %s, %s", string(out), err)
	}

	certData, err := ioutil.ReadFile(unitCertFile)
	if err != nil {
		return "", err
	}

	return string(certData), nil
}

func getKey(filePath string) (key *rsa.PrivateKey, err error) {
	keyData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	keyPem, _ := pem.Decode(keyData)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(keyPem.Bytes)
}

func checkFileURL(strURL string, file string) (err error) {
	valURL, err := url.Parse(strURL)
	if err != nil {
		return err
	}

	if file != valURL.Path {
		return fmt.Errorf("cert file mismatch: %s !=%s", strURL, file)
	}

	return nil
}

func checkHandleURL(keyURL string, handle tpmutil.Handle) (err error) {
	urlVal, err := url.Parse(keyURL)
	if err != nil {
		return err
	}

	handleVal, err := strconv.ParseUint(urlVal.Hostname(), 0, 32)
	if err != nil {
		return err
	}

	if handle != tpmutil.Handle(handleVal) {
		return fmt.Errorf("handle mismatch: %s != 0x%X", keyURL, handle)
	}

	return nil
}

func getPersistentHandles() (handles []tpmutil.Handle, err error) {
	values, _, err := tpm2.GetCapability(tpmSimulator, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst), uint32(tpm2.PersistentFirst))
	if err != nil {
		return nil, err
	}

	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			return nil, errors.New("wrong TPM data format")
		}

		handles = append(handles, handle)
	}

	return handles, nil
}

func getKeyFiles(storagePath string) (files []string, err error) {
	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil, err
	}

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		if path.Ext(item.Name()) != ".key" {
			continue
		}

		files = append(files, path.Join(storagePath, item.Name()))
	}

	return files, nil
}

func getCertFiles(storagePath string) (files []string, err error) {
	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil, err
	}

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		if path.Ext(item.Name()) != ".crt" {
			continue
		}

		files = append(files, path.Join(storagePath, item.Name()))
	}

	return files, nil
}
