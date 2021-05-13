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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
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
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/testtools"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/tpmkey"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

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

type createModuleType func(doReset bool) (module certhandler.CertModule, err error)

/*******************************************************************************
 * Var
 ******************************************************************************/

var tmpDir string
var certStorage string
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

	certStorage = path.Join(tmpDir, "certStorage")

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
	numKeys := 16

	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		for _, algorithm := range []string{cryptutils.AlgRSA, cryptutils.AlgECC} {
			module, err := createModule(true)
			if err != nil {
				t.Fatalf("Can't create module: %s", err)
			}
			defer module.Close()

			var maxPendingKeys = 0
			var maxApplyKeys = 0

			switch module.(type) {
			case *swmodule.SWModule:
				maxPendingKeys = 16
				maxApplyKeys = 16

			case *tpmmodule.TPMModule:
				maxPendingKeys = 16
				maxApplyKeys = 7
			}

			// Set owner

			password := "password"

			if err = module.SetOwner(password); err != nil {
				t.Fatalf("Can't set owner: %s", err)
			}

			// Create keys

			keys := make([]crypto.PrivateKey, 0)

			for i := 0; i < numKeys; i++ {
				key, err := module.CreateKey(password, algorithm)
				if err != nil {
					t.Fatalf("Can't create key: %s", err)
				}

				keys = append(keys, key)
			}

			if numKeys >= maxPendingKeys {
				keys = keys[numKeys-maxPendingKeys : numKeys-maxPendingKeys+maxApplyKeys]
			}

			for _, key := range keys {
				// Create CSR

				csr, err := testtools.CreateCSR(key)
				if err != nil {
					t.Fatalf("Can't create CSR: %s", err)
				}

				// Verify CSR

				csrFile := path.Join(tmpDir, "data.csr")

				if err = ioutil.WriteFile(csrFile, csr, 0644); err != nil {
					t.Fatalf("Can't write CSR to file: %s", err)
				}

				out, err := exec.Command("openssl", "req", "-text", "-noout", "-verify", "-inform", "PEM", "-in", csrFile).CombinedOutput()
				if err != nil {
					t.Fatalf("Can't verify CSR: %s, %s", out, err)
				}

				// Apply certificate

				cert, err := testtools.CreateCertificate(tmpDir, csr)
				if err != nil {
					t.Fatalf("Can't generate certificate: %s", err)
				}

				certInfo, _, err := module.ApplyCertificate(cert)
				if err != nil {
					t.Fatalf("Can't apply certificate: %s", err)
				}

				// Check encrypt/decrypt with private key

				keyVal, err := url.Parse(certInfo.KeyURL)
				if err != nil {
					t.Fatalf("Wrong key URL: %s", certInfo.KeyURL)
				}

				var currentKey crypto.PrivateKey

				switch keyVal.Scheme {
				case cryptutils.SchemeFile:
					if currentKey, err = cryptutils.LoadKey(keyVal.Path); err != nil {
						t.Fatalf("Can't get key: %s", err)
					}

				case cryptutils.SchemeTPM:
					handle, err := strconv.ParseUint(keyVal.Hostname(), 0, 32)
					if err != nil {
						t.Fatalf("Can't parse key URL: %s", err)
					}

					if currentKey, err = tpmkey.CreateFromPersistent(tpmSimulator, tpmutil.Handle(handle)); err != nil {
						t.Fatalf("Can't create key: %s", err)
					}

				default:
					t.Fatalf("Unsupported key scheme: %s", keyVal.Scheme)
				}

				// Check descryption

				if decrypter, ok := currentKey.(crypto.Decrypter); ok {
					originMessage := []byte("This is origin message")

					rsaPublic, ok := decrypter.Public().(*rsa.PublicKey)
					if !ok {
						t.Fatal("Key is not RSA key")
					}

					encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublic, originMessage)
					if err != nil {
						t.Fatalf("Can't encrypt message: %s", err)
					}

					decryptedData, err := decrypter.Decrypt(rand.Reader, encryptedData, nil)
					if err != nil {
						t.Fatalf("Can't decrypt message: %s", err)
					}

					if !bytes.Equal(originMessage, decryptedData) {
						t.Error("Decrypt error")
					}
				}

				// Check signing

				if signer, ok := currentKey.(crypto.Signer); ok {
					originMessage := []byte("This is origin message")

					hashFunc := crypto.SHA256

					h := hashFunc.New()
					h.Write(originMessage)

					signature, err := signer.Sign(rand.Reader, h.Sum(nil), hashFunc)
					if err != nil {
						t.Fatalf("Can't sign digest: %s", err)
					}

					switch publicKey := signer.Public().(type) {
					case *rsa.PublicKey:
						if err = rsa.VerifyPKCS1v15(publicKey, hashFunc, h.Sum(nil), signature); err != nil {
							t.Fatalf("Verify signature error: %s", err)
						}

					case *ecdsa.PublicKey:
						if !verifyASN1(publicKey, h.Sum(nil), signature) {
							t.Fatalf("Verify signature error: %s", err)
						}

					default:
						t.Fatal("Unsupported key type")
					}
				}
			}
		}
	}
}

func TestValidateCertificates(t *testing.T) {
	// Test items:
	// * valid       - cert and key are valid
	// * onlyCert    - cert without key
	// * onlyKey     - key without cert
	// * invalidFile - invalid file

	testData := []string{"valid", "onlyCert", "valid", "onlyKey", "invalidFile"}

	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		module, err := createModule(true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}
		defer module.Close()

		// Set owner

		password := "password"

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		var goodItems []certhandler.CertInfo

		for _, item := range testData {
			// Create key

			key, err := module.CreateKey(password, cryptutils.AlgRSA)
			if err != nil {
				t.Fatalf("Can't create key: %s", err)
			}

			// Create CSR

			csr, err := testtools.CreateCSR(key)
			if err != nil {
				t.Fatalf("Can't create CSR: %s", err)
			}

			// Apply certificate

			cert, err := testtools.CreateCertificate(tmpDir, csr)
			if err != nil {
				t.Fatalf("Can't generate certificate: %s", err)
			}

			certInfo, _, err := module.ApplyCertificate(cert)
			if err != nil {
				t.Fatalf("Can't apply certificate: %s", err)
			}

			certVal, err := url.Parse(certInfo.CertURL)
			if err != nil {
				t.Fatalf("Can't parse cert URL: %s", err)
			}

			keyVal, err := url.Parse(certInfo.KeyURL)
			if err != nil {
				t.Fatalf("Can't parse key URL: %s", err)
			}

			switch item {
			case "onlyKey":
				if err = os.Remove(certVal.Path); err != nil {
					t.Errorf("Can't remove cert file: %s", err)
				}

			case "onlyCert":
				switch keyVal.Scheme {
				case cryptutils.SchemeFile:
					if err = os.Remove(keyVal.Path); err != nil {
						t.Errorf("Can't remove key file: %s", err)
					}

				case cryptutils.SchemeTPM:
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

			case "invalidFile":
				if err = ioutil.WriteFile(certVal.Path, []byte{}, 0644); err != nil {
					t.Errorf("Can't write file: %s", err)
				}

			default:
				goodItems = append(goodItems, certInfo)
			}
		}

		certInfos, invalidCerts, invalidKeys, err := module.ValidateCertificates()
		if err != nil {
			t.Fatalf("Can't validate certificates: %s", err)
		}

		checkInfo := make([]certhandler.CertInfo, len(certInfos))

		copy(checkInfo, certInfos)

		for _, goodItem := range goodItems {
			found := false

			infoIndex := 0

			for i, info := range checkInfo {
				if info == goodItem {
					found = true
					infoIndex = i

					break
				}
			}

			if !found {
				t.Errorf("Expected item not found, certURL: %s, keyURL: %s", goodItem.CertURL, goodItem.KeyURL)
			} else {
				checkInfo = append(checkInfo[:infoIndex], checkInfo[infoIndex+1:]...)
			}
		}

		for _, badItem := range checkInfo {
			t.Errorf("Item should not be found, certURL: %s, keyURL: %s", badItem.CertURL, badItem.KeyURL)
		}

		// Remove invalid certs

		for _, certURL := range invalidCerts {
			if err = module.RemoveCertificate(certURL, password); err != nil {
				t.Fatalf("Can't remove certificate: %s", err)
			}
		}

		// Remove invalid keys

		for _, keyURL := range invalidKeys {
			if err = module.RemoveKey(keyURL, password); err != nil {
				t.Fatalf("Can't remove key: %s", err)
			}
		}

		// Check cert files

		certURLs := make([]string, 0, len(certInfos))

		for _, info := range certInfos {
			certURLs = append(certURLs, info.CertURL)
		}

		checkCertURLs(t, certStorage, certURLs)

		// Check key files

		switch module.(type) {
		case *swmodule.SWModule:
			keyURLs := make([]string, 0, len(certInfos))

			for _, info := range certInfos {
				keyURLs = append(keyURLs, info.KeyURL)
			}

			checkKeyURLs(t, certStorage, keyURLs)

		case *tpmmodule.TPMModule:
			keyURLs := make([]string, 0, len(certInfos))

			for _, info := range certInfos {
				keyURLs = append(keyURLs, info.KeyURL)
			}

			checkHandleURLs(t, certStorage, keyURLs)
		}
	}
}

func TestSetOwnerClear(t *testing.T) {
	for _, createModule := range []createModuleType{createSwModule, createTpmModule} {
		module, err := createModule(true)
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

		// Create key

		key, err := module.CreateKey(password, cryptutils.AlgRSA)
		if err != nil {
			t.Fatalf("Can't create key: %s", err)
		}

		// Create CSR

		csr, err := testtools.CreateCSR(key)
		if err != nil {
			t.Fatalf("Can't create CSR: %s", err)
		}

		// Apply certificate

		cert, err := testtools.CreateCertificate(tmpDir, csr)
		if err != nil {
			t.Fatalf("Can't generate certificate: %s", err)
		}

		certInfo, _, err := module.ApplyCertificate(cert)
		if err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}

		// Check key files

		keyVal, err := url.Parse(certInfo.KeyURL)
		if err != nil {
			t.Fatalf("Wrong key URL: %s", certInfo.KeyURL)
		}

		checkCertURLs(t, certStorage, []string{certInfo.CertURL})

		switch keyVal.Scheme {
		case cryptutils.SchemeFile:
			checkKeyURLs(t, certStorage, []string{certInfo.KeyURL})

		case cryptutils.SchemeTPM:
			checkHandleURLs(t, certStorage, []string{certInfo.KeyURL})

		default:
			t.Errorf("Unsupported key scheme: %s", keyVal.Scheme)

			continue
		}

		// Clear

		if err = module.Clear(); err != nil {
			t.Fatalf("Can't clear: %s", err)
		}

		checkCertURLs(t, certStorage, nil)

		switch keyVal.Scheme {
		case cryptutils.SchemeFile:
			checkKeyURLs(t, certStorage, nil)

		case cryptutils.SchemeTPM:
			checkHandleURLs(t, certStorage, nil)

		default:
			t.Errorf("Unsupported key scheme: %s", keyVal.Scheme)

			continue
		}
	}
}

// Test for TPM only
func TestTPMNonZeroDictionaryAttackParameters(t *testing.T) {
	password := "password"

	module, err := createTpmModule(true)
	if err != nil {
		t.Fatalf("Can't create module: %s", err)
	}
	defer module.Close()

	if err = module.SetOwner(password); err != nil {
		t.Fatalf("Can't set owner: %s", err)
	}

	caps, _, err := tpm2.GetCapability(tpmSimulator, tpm2.CapabilityTPMProperties, 3, uint32(tpm2.MaxAuthFail))
	if err != nil {
		t.Fatalf("Failed to get TPM capabilities: %v", err)
	}
	maxRetries, recoveryTime, lockoutRecovery := caps[0].(tpm2.TaggedProperty).Value,
		caps[1].(tpm2.TaggedProperty).Value, caps[2].(tpm2.TaggedProperty).Value

	if maxRetries == 0 {
		t.Error("maxTries is 0")
	}
	if recoveryTime == 0 {
		t.Error("recoveryTime is 0")
	}
	if lockoutRecovery == 0 {
		t.Error("lockoutRecovery is 0")
	}
}

// Test for TPM only
func TestTPMDictionaryAttackLockoutCounter(t *testing.T) {
	password := "password"
	pcrSelection7 := tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}

	module, err := createTpmModule(true)
	if err != nil {
		t.Fatalf("Can't create module: %s", err)
	}
	defer module.Close()

	if err = module.SetOwner(password); err != nil {
		t.Fatalf("Can't set owner: %s", err)
	}

	handle, _, err := tpm2.CreatePrimary(tpmSimulator, tpm2.HandleOwner, pcrSelection7, password, "", tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgNull,
				Hash: tpm2.AlgNull,
			},
			KeyBits: 2048,
		},
	})
	if err != nil {
		t.Fatalf("Creating primary key failed: %v", err)
	}
	defer tpm2.FlushContext(tpmSimulator, handle)

	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	label := "label"

	encrypted, err := tpm2.RSAEncrypt(tpmSimulator, handle, bytes.Repeat([]byte("a"), 190), scheme, label)
	if err != nil {
		t.Fatalf("RSA encryption failed: %v", err)
	}

	// Try RSADecrypt with bad password
	if _, err = tpm2.RSADecrypt(tpmSimulator, handle, "bad password", encrypted, scheme, label); err != nil {
		if sessionErr, ok := err.(tpm2.SessionError); !ok || sessionErr.Code != tpm2.RCAuthFail {
			t.Fatalf("RSA decryption failed with unexpected error: %v", err)
		}
	}

	caps, _, err := tpm2.GetCapability(tpmSimulator, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.LockoutCounter))
	if err != nil {
		t.Fatalf("Failed to get capabilities: %v", err)
	}
	if caps[0].(tpm2.TaggedProperty).Value != 1 {
		t.Errorf("Got %d, expected 1", caps[0].(tpm2.TaggedProperty).Value)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func createSwModule(doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(certStorage); err != nil {
			return nil, err
		}
	}

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s"}`, certStorage))

	return swmodule.New("test", config)
}

func createTpmModule(doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(certStorage); err != nil {
			return nil, err
		}

		if err = tpmSimulator.ManufactureReset(); err != nil {
			return nil, err
		}
	}

	// Dictionary attack paramters
	lockoutMaxRetries, recoveryTime, lockoutRecoveryTime := 3, 1000, 1000

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s", "lockoutMaxTry": %d,
		"recoveryTime": %d, "lockoutRecoveryTime": %d}`, certStorage, lockoutMaxRetries, recoveryTime, lockoutRecoveryTime))

	return tpmmodule.New("test", config, tpmSimulator)
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

func checkUrls(t *testing.T, expectedURLs, existingURLs []string) {
	t.Helper()

	for _, expected := range expectedURLs {
		found := false

		for i, existing := range existingURLs {
			if expected == existing {
				found = true
				existingURLs = append(existingURLs[:i], existingURLs[i+1:]...)

				break
			}
		}

		if !found {
			t.Errorf("Expected URL %s not found", expected)
		}
	}

	for _, existing := range existingURLs {
		t.Errorf("Unexpected URL %s found", existing)
	}
}

func checkHandleURLs(t *testing.T, storagePath string, expectedURLs []string) {
	values, _, err := tpm2.GetCapability(tpmSimulator, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst), uint32(tpm2.PersistentFirst))
	if err != nil {
		t.Fatalf("Can't read persistent storage: %s", err)
	}

	existingURLs := make([]string, 0)

	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			t.Fatal("Wrong TPM data format")
		}

		keyURL := url.URL{Scheme: cryptutils.SchemeTPM, Host: fmt.Sprintf("0x%X", handle)}

		existingURLs = append(existingURLs, keyURL.String())
	}

	checkUrls(t, expectedURLs, existingURLs)
}

func checkKeyURLs(t *testing.T, storagePath string, expectedURLs []string) {
	t.Helper()

	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		t.Fatalf("Can't read storage dir: %s", err)
	}

	existingURLs := make([]string, 0)

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		absItemPath := path.Join(storagePath, item.Name())

		if _, err = cryptutils.LoadKey(absItemPath); err != nil {
			continue
		}

		keyURL := url.URL{Scheme: cryptutils.SchemeFile, Path: absItemPath}

		existingURLs = append(existingURLs, keyURL.String())
	}

	checkUrls(t, expectedURLs, existingURLs)
}

func checkCertURLs(t *testing.T, storagePath string, expectedURLs []string) {
	t.Helper()

	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		t.Fatalf("Can't read storage dir: %s", err)
	}

	existingURLs := make([]string, 0)

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		absItemPath := path.Join(storagePath, item.Name())

		if _, err = cryptutils.LoadCertificate(absItemPath); err != nil {
			continue
		}

		certURL := url.URL{Scheme: cryptutils.SchemeFile, Path: absItemPath}

		existingURLs = append(existingURLs, certURL.String())
	}

	checkUrls(t, expectedURLs, existingURLs)
}

func verifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)

	input := cryptobyte.String(sig)

	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() || !inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) || !inner.Empty() {
		return false

	}

	return ecdsa.Verify(pub, hash, r, s)
}
