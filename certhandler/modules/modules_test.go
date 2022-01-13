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

package certmodules_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"unsafe"

	"github.com/ThalesIgnite/crypto11"
	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/aoscloud/aos_common/utils/testtools"
	"github.com/aoscloud/aos_common/utils/tpmkey"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/aoscloud/aos_iamanager/certhandler"
	"github.com/aoscloud/aos_iamanager/certhandler/modules/pkcs11module"
	"github.com/aoscloud/aos_iamanager/certhandler/modules/swmodule"
	"github.com/aoscloud/aos_iamanager/certhandler/modules/tpmmodule"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	pkcs11LibPath = "/usr/lib/softhsm/libsofthsm2.so"
	pkcs11DBPath  = "/var/lib/softhsm/tokens/"
)

const (
	passwordStr = "password"
	keyStr      = "key"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type createModuleType func(doReset bool) (module certhandler.CertModule, err error)

/*******************************************************************************
 * Var
 ******************************************************************************/

var (
	tmpDir       string
	certStorage  string
	tpmSimulator *simulator.Simulator
)

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
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
	numKeys := 30
	maxPendingKeys := 16
	maxApplyKeys := 7

	for _, createModule := range []createModuleType{createSwModule, createTpmModule, createPKCS11Module} {
		for _, algorithm := range []string{cryptutils.AlgRSA, cryptutils.AlgECC} {
			module, err := createModule(true)
			if err != nil {
				t.Fatalf("Can't create module: %s", err)
			}

			// Set owner

			password := passwordStr

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

			if numKeys > maxPendingKeys {
				keys = keys[numKeys-maxPendingKeys : numKeys-maxPendingKeys+maxApplyKeys]
			} else {
				keys = keys[:maxApplyKeys]
			}

			var certInfos []certhandler.CertInfo

			for _, key := range keys {
				csr, err := testtools.CreateCSR(key)
				if err != nil {
					t.Fatalf("Can't create CSR: %s", err)
				}

				// Verify CSR

				csrFile := path.Join(tmpDir, "data.csr")

				if err = ioutil.WriteFile(csrFile, csr, 0o600); err != nil {
					t.Fatalf("Can't write CSR to file: %s", err)
				}

				out, err := exec.Command(
					"openssl", "req", "-text", "-noout", "-verify", "-inform", "PEM", "-in", csrFile).CombinedOutput()
				if err != nil {
					t.Fatalf("Can't verify CSR: %s, %s", out, err)
				}

				// Apply certificate

				cert, err := testtools.CreateCertificate(tmpDir, csr)
				if err != nil {
					t.Fatalf("Can't generate certificate: %s", err)
				}

				x509Certs, err := cryptutils.PEMToX509Cert(cert)
				if err != nil {
					t.Fatalf("Can't convert certificate: %s", err)
				}

				certInfo, _, err := module.ApplyCertificate(x509Certs)
				if err != nil {
					t.Fatalf("Can't apply certificate: %s", err)
				}

				certInfos = append(certInfos, certInfo)
			}

			if err = module.Close(); err != nil {
				t.Errorf("Can't close module: %s", err)
			}

			// Check encrypt/decrypt with private key

			var pkcs11Ctx *crypto11.Context

			for _, certInfo := range certInfos {
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

				case cryptutils.SchemePKCS11:
					opaqueValues, err := url.ParseQuery(keyVal.Opaque)
					if err != nil {
						t.Fatalf("Can't parse opaque: %s", err)
					}

					if pkcs11Ctx == nil {
						if pkcs11Ctx, err = crypto11.Configure(&crypto11.Config{
							Path:       pkcs11LibPath,
							TokenLabel: opaqueValues["token"][0],
							Pin:        keyVal.Query()["pin-value"][0],
						}); err != nil {
							t.Fatalf("Can't init pkcs11 context: %s", err)
						}
					}

					if currentKey, err = pkcs11Ctx.FindKeyPair([]byte(opaqueValues["id"][0]), nil); err != nil {
						t.Fatalf("Can't find key: %s", err)
					}

					if currentKey == nil {
						t.Fatal("Key not found")
					}

				default:
					t.Fatalf("Unsupported key scheme: %s", keyVal.Scheme)
				}

				switch currentKey.(type) {
				case crypto.Decrypter:
				case crypto.Signer:
				default:
					t.Fatalf("Key %s doesn't support required interface", certInfo.KeyURL)
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

			// Close PKCS11 context

			if pkcs11Ctx != nil {
				if err = pkcs11Ctx.Close(); err != nil {
					t.Fatalf("Can't close pkcs11 context: %s", err)
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
	testData := []string{"valid", "onlyCert", "valid", "onlyKey", "valid"}

	for _, createModule := range []createModuleType{createSwModule, createTpmModule, createPKCS11Module} {
		module, err := createModule(true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}

		// Set owner

		password := passwordStr

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		var goodItems []certhandler.CertInfo

		for _, item := range testData {
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

			x509Certs, err := cryptutils.PEMToX509Cert(cert)
			if err != nil {
				t.Fatalf("Can't convert certificate: %s", err)
			}

			certInfo, _, err := module.ApplyCertificate(x509Certs)
			if err != nil {
				t.Fatalf("Can't apply certificate: %s", err)
			}

			switch item {
			case "onlyKey":
				if err = module.RemoveCertificate(certInfo.CertURL, password); err != nil {
					t.Fatalf("Can't remove certificate: %s", err)
				}

			case "onlyCert":
				if err = module.RemoveKey(certInfo.KeyURL, password); err != nil {
					t.Fatalf("Can't remove certificate: %s", err)
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

		if err = module.Close(); err != nil {
			t.Fatalf("Can't close module: %s", err)
		}

		// Check cert files

		certURLs := make([]string, 0, len(certInfos))

		for _, info := range certInfos {
			certURLs = append(certURLs, info.CertURL)
		}

		checkLocationURLs(t, certURLs[0], "cert", certURLs)

		// Check key files

		keyURLs := make([]string, 0, len(certInfos))

		for _, info := range certInfos {
			keyURLs = append(keyURLs, info.KeyURL)
		}

		checkLocationURLs(t, keyURLs[0], "key", keyURLs)
	}
}

func TestSetOwnerClear(t *testing.T) {
	for _, createModule := range []createModuleType{createSwModule, createTpmModule, createPKCS11Module} {
		module, err := createModule(true)
		if err != nil {
			t.Fatalf("Can't create module: %s", err)
		}

		// Set owner

		password := passwordStr

		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
		}

		// Check if we can set owner twice
		if err = module.SetOwner(password); err != nil {
			t.Fatalf("Can't set owner: %s", err)
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

		x509Certs, err := cryptutils.PEMToX509Cert(cert)
		if err != nil {
			t.Fatalf("Can't convert certificate: %s", err)
		}

		certInfo, _, err := module.ApplyCertificate(x509Certs)
		if err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}

		if err = module.Close(); err != nil {
			t.Fatalf("Can't close module: %s", err)
		}

		// Check key files

		checkLocationURLs(t, certInfo.CertURL, "cert", []string{certInfo.CertURL})
		checkLocationURLs(t, certInfo.KeyURL, "key", []string{certInfo.KeyURL})

		// Clear

		if module, err = createModule(false); err != nil {
			t.Fatalf("Can't create module: %s", err)
		}

		if err = module.Clear(); err != nil {
			t.Fatalf("Can't clear: %s", err)
		}

		if err = module.Close(); err != nil {
			t.Fatalf("Can't close module: %s", err)
		}

		checkLocationURLs(t, certInfo.CertURL, "cert", nil)
		checkLocationURLs(t, certInfo.KeyURL, "key", nil)
	}
}

// Test for TPM only.
func TestTPMNonZeroDictionaryAttackParameters(t *testing.T) {
	password := passwordStr

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

// Test for TPM only.
func TestTPMDictionaryAttackLockoutCounter(t *testing.T) {
	password := passwordStr
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
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent |
			tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
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

	defer func() {
		if flushErr := tpm2.FlushContext(tpmSimulator, handle); flushErr != nil {
			t.Errorf("Can't flush context: %s", flushErr)
		}
	}()

	scheme := &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}
	label := "label"

	encrypted, err := tpm2.RSAEncrypt(tpmSimulator, handle, bytes.Repeat([]byte("a"), 190), scheme, label)
	if err != nil {
		t.Fatalf("RSA encryption failed: %v", err)
	}

	// Try RSADecrypt with bad password
	if _, err = tpm2.RSADecrypt(tpmSimulator, handle, "bad password", encrypted, scheme, label); err != nil {
		var sessionErr tpm2.SessionError

		if !errors.As(err, &sessionErr) || sessionErr.Code != tpm2.RCAuthFail {
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

func TestPKCS11ValidateCertChain(t *testing.T) {
	module, err := createPKCS11Module(true)
	if err != nil {
		t.Fatalf("Can't create module: %s", err)
	}

	// Set owner

	password := passwordStr

	if err = module.SetOwner(password); err != nil {
		t.Fatalf("Can't set owner: %s", err)
	}

	// Generate valid certificates

	numValidCerts := 5

	for i := 0; i < numValidCerts; i++ {
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

		x509Certs, err := cryptutils.PEMToX509Cert(cert)
		if err != nil {
			t.Fatalf("Can't convert certificate: %s", err)
		}

		if _, _, err = module.ApplyCertificate(x509Certs); err != nil {
			t.Fatalf("Can't apply certificate: %s", err)
		}
	}

	if err = module.Close(); err != nil {
		t.Fatalf("Can't close module: %s", err)
	}

	data, err := ioutil.ReadFile(path.Join(tmpDir, "userPin.txt"))
	if err != nil {
		t.Fatalf("Can't read user pin: %s", err)
	}

	userPin := string(data)

	pkcs11Ctx, err := crypto11.Configure(&crypto11.Config{
		Path: pkcs11LibPath, TokenLabel: "aos", Pin: userPin,
	})
	if err != nil {
		t.Fatalf("Can't create PKCS11 context: %s", err)
	}

	// Generate invalid certificates

	numInvalidCerts := 10

	var expectedInvalidCerts []string

	for i := 0; i < numInvalidCerts; i++ {
		serial, err := rand.Int(rand.Reader, big.NewInt(1024))
		if err != nil {
			t.Fatalf("Can't generate random: %s", err)
		}

		cert := &x509.Certificate{
			SerialNumber: serial,
			RawSubject:   []byte(uuid.New().String()),
			RawIssuer:    []byte(uuid.New().String()),
		}

		id := uuid.New().String()

		if err = pkcs11Ctx.ImportCertificate([]byte(id), cert); err != nil {
			t.Fatalf("Can't import certificate: %s", err)
		}

		expectedInvalidCerts = append(expectedInvalidCerts, createPkcs11URL("aos", userPin, "", id))
	}

	if err = pkcs11Ctx.Close(); err != nil {
		t.Fatalf("Can't close PKCS11 context: %s", err)
	}

	if module, err = createPKCS11Module(false); err != nil {
		t.Fatalf("Can't create module: %s", err)
	}

	_, invalidCerts, _, err := module.ValidateCertificates()
	if err != nil {
		t.Fatalf("Can't validate certificates: %s", err)
	}

	if err = module.Close(); err != nil {
		t.Fatalf("Can't close module: %s", err)
	}

	checkUrls(t, expectedInvalidCerts, invalidCerts)
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func createSwModule(doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(certStorage); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s"}`, certStorage))

	if module, err = swmodule.New("test", config); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return module, nil
}

func createTpmModule(doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err := os.RemoveAll(certStorage); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = tpmSimulator.ManufactureReset(); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	// Dictionary attack parameters
	lockoutMaxRetries, recoveryTime, lockoutRecoveryTime := 3, 1000, 1000

	config := json.RawMessage(fmt.Sprintf(`{"storagePath":"%s", "lockoutMaxTry": %d,
		"recoveryTime": %d, "lockoutRecoveryTime": %d}`, certStorage, lockoutMaxRetries, recoveryTime, lockoutRecoveryTime))

	if module, err = tpmmodule.New("test", config, tpmSimulator); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return module, nil
}

func createPKCS11Module(doReset bool) (module certhandler.CertModule, err error) {
	if doReset {
		if err = os.RemoveAll(pkcs11DBPath); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = os.MkdirAll(pkcs11DBPath, 0o755); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	config := json.RawMessage(fmt.Sprintf(
		`{"library":"%s","userPinPath":"%s"}`, pkcs11LibPath, path.Join(tmpDir, "userPin.txt")))

	if module, err = pkcs11module.New("test", config); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return module, nil
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

func getExistingFileItems(itemType, storagePath string) (existingURLs []string, err error) {
	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		absItemPath := path.Join(storagePath, item.Name())

		switch itemType {
		case "cert":
			if _, err = cryptutils.LoadCertificate(absItemPath); err != nil {
				continue
			}

		case keyStr:
			if _, err = cryptutils.LoadKey(absItemPath); err != nil {
				continue
			}

		default:
			return nil, aoserrors.Errorf("unsupported item type: %s", itemType)
		}

		keyURL := url.URL{Scheme: cryptutils.SchemeFile, Path: absItemPath}

		existingURLs = append(existingURLs, keyURL.String())
	}

	return existingURLs, nil
}

func getExistingTPMItems(itemType string) (existingURLs []string, err error) {
	switch itemType {
	case keyStr:

	default:
		return nil, aoserrors.Errorf("unsupported item type: %s", itemType)
	}

	values, _, err := tpm2.GetCapability(tpmSimulator, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst), uint32(tpm2.PersistentFirst))
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			return nil, aoserrors.New("wrong TPM data format")
		}

		keyURL := url.URL{Scheme: cryptutils.SchemeTPM, Host: fmt.Sprintf("0x%X", handle)}

		existingURLs = append(existingURLs, keyURL.String())
	}

	return existingURLs, nil
}

func createPkcs11URL(token, userPin, label, id string) (urlStr string) {
	opaque := fmt.Sprintf("token=%s", token)

	if label != "" {
		opaque += fmt.Sprintf(";object=%s", label)
	}

	if id != "" {
		opaque += fmt.Sprintf(";id=%s", id)
	}

	query := url.Values{}

	query.Set("pin-value", userPin)

	pkcs11URL := &url.URL{Scheme: cryptutils.SchemePKCS11, Opaque: opaque, RawQuery: query.Encode()}

	return pkcs11URL.String()
}

func getExistingPKCS11Items(token, userPin, label, itemType string) (existingURLs []string, err error) {
	pkcs11Ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       pkcs11LibPath,
		TokenLabel: token,
		Pin:        userPin,
	})
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}
	defer pkcs11Ctx.Close()

	switch itemType {
	case "cert":
		ctx := (*pkcs11.Ctx)(unsafe.Pointer(reflect.ValueOf(pkcs11Ctx).Elem().FieldByName("ctx").Pointer()))
		session := pkcs11.SessionHandle(reflect.ValueOf(pkcs11Ctx).Elem().FieldByName("persistentSession").Uint())

		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}

		if err = ctx.FindObjectsInit(session, template); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		defer func() {
			if objErr := ctx.FindObjectsFinal(session); objErr != nil {
				if err == nil {
					err = aoserrors.Wrap(objErr)
				}
			}
		}()

		for {
			handles, _, err := ctx.FindObjects(session, 32)
			if err != nil {
				return nil, aoserrors.Wrap(err)
			}

			for _, handle := range handles {
				attributes, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				})
				if err != nil {
					return nil, aoserrors.Wrap(err)
				}

				existingURLs = append(existingURLs, createPkcs11URL(token, userPin, label, string(attributes[0].Value)))
			}

			if len(handles) == 0 {
				break
			}
		}

	case keyStr:
		keys, err := pkcs11Ctx.FindKeyPairs(nil, []byte(label))
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		for _, key := range keys {
			attr, err := pkcs11Ctx.GetAttribute(key, crypto11.CkaId)
			if err != nil {
				return nil, aoserrors.Wrap(err)
			}

			existingURLs = append(existingURLs, createPkcs11URL(token, userPin, label, string(attr.Value)))
		}

	default:
		return nil, aoserrors.Errorf("unsupported item type: %s", itemType)
	}

	return existingURLs, nil
}

func checkLocationURLs(t *testing.T, location, itemType string, expectedURLs []string) {
	t.Helper()

	var existingURLs []string

	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Can't parse key location: %s", err)
	}

	switch locationURL.Scheme {
	case cryptutils.SchemeFile:
		if existingURLs, err = getExistingFileItems(itemType, filepath.Dir(locationURL.Path)); err != nil {
			t.Fatalf("Can't get existing file items: %s", err)
		}

	case cryptutils.SchemeTPM:
		if existingURLs, err = getExistingTPMItems(itemType); err != nil {
			t.Fatalf("Can't get existing file items: %s", err)
		}

	case cryptutils.SchemePKCS11:
		opaqueValues, err := url.ParseQuery(locationURL.Opaque)
		if err != nil {
			t.Fatalf("Can't parse opaque: %s", err)
		}

		if existingURLs, err = getExistingPKCS11Items(
			opaqueValues["token"][0],
			locationURL.Query()["pin-value"][0],
			opaqueValues["object"][0], itemType); err != nil {
			t.Fatalf("Can't get existing file items: %s", err)
		}

	default:
		t.Fatalf("Unsupported key scheme: %s", locationURL.Scheme)
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
