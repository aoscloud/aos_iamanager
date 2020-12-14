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

package swmodule

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	crtExt = ".crt"
	keyExt = ".key"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// SWModule SW certificate module
type SWModule struct {
	certType string
	config   moduleConfig
	storage  certhandler.CertStorage

	currentKey *rsa.PrivateKey
}

type moduleConfig struct {
	StoragePath string `json:"storagePath"`
	MaxItems    int    `json:"maxItems"`
}

/*******************************************************************************
 * Types
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage, storage certhandler.CertStorage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create SW module")

	swModule := &SWModule{certType: certType, storage: storage}

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &swModule.config); err != nil {
			return nil, err
		}
	}

	if err = os.MkdirAll(swModule.config.StoragePath, 0755); err != nil {
		return nil, err
	}

	return swModule, nil
}

// Close closes SW module
func (module *SWModule) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close SW module")

	return err
}

// SyncStorage syncs cert storage
func (module *SWModule) SyncStorage() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Sync storage")

	if err = module.updateStorage(); err != nil {
		return err
	}

	files, err := getFilesByExt(module.config.StoragePath, crtExt)
	if err != nil {
		return err
	}

	infos, err := module.storage.GetCertificates(module.certType)
	if err != nil {
		return err
	}

	// FS certs that need to be updated

	var updateFiles []string

	for _, file := range files {
		found := false

		for _, info := range infos {
			if fileToURL(file) == info.CertURL {
				found = true

				break
			}
		}

		if !found {
			updateFiles = append(updateFiles, file)
		}
	}

	if err = module.updateCerts(updateFiles); err != nil {
		return err
	}

	return nil
}

// CreateKeys creates key pair
func (module *SWModule) CreateKeys(systemID, password string) (csr string, err error) {
	log.WithFields(log.Fields{"certType": module.certType, "systemID": systemID}).Debug("Create keys")

	if module.currentKey != nil {
		log.Warning("Current key exists. Flushing...")
	}

	if module.currentKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return "", err
	}

	csrDER, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{Subject: pkix.Name{CommonName: systemID}}, module.currentKey)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

// ApplyCertificate applies certificate
func (module *SWModule) ApplyCertificate(cert string) (certURL, keyURL string, err error) {
	if module.currentKey == nil {
		return "", "", errors.New("no key created")
	}
	defer func() { module.currentKey = nil }()

	block, _ := pem.Decode([]byte(cert))

	if block == nil {
		return "", "", errors.New("invalid PEM Block")
	}

	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return "", "", errors.New("invalid PEM Block")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}

	if err = checkCert(x509Cert, module.currentKey.Public()); err != nil {
		return "", "", err
	}

	certFileName, err := saveCert(module.config.StoragePath, x509Cert)
	if err != nil {
		return "", "", err
	}

	keyFileName, err := saveKey(module.config.StoragePath, module.currentKey)
	if err != nil {
		return "", "", err
	}

	certURL = fileToURL(certFileName)
	keyURL = fileToURL(keyFileName)

	if err = module.storeCert(x509Cert, certURL, keyURL); err != nil {
		return "", "", err
	}

	certs, err := module.storage.GetCertificates(module.certType)
	if err != nil {
		log.Errorf("Can' get certificates: %s", err)
	}

	for len(certs) > module.config.MaxItems && module.config.MaxItems != 0 {
		log.Warnf("Current cert count exceeds max count: %d > %d. Remove old certs", len(certs), module.config.MaxItems)

		var minTime time.Time
		var minIndex int

		for i, cert := range certs {
			if minTime.IsZero() || cert.NotAfter.Before(minTime) {
				minTime = cert.NotAfter
				minIndex = i
			}
		}

		if err = module.removeCert(certs[minIndex]); err != nil {
			log.Errorf("Can't delete old certificate: %s", err)
		}

		certs = append(certs[:minIndex], certs[minIndex+1:]...)
	}

	return certURL, keyURL, nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func pemToX509Cert(certPem string) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(certPem))

	if block == nil {
		return nil, errors.New("invalid PEM Block")
	}

	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("invalid PEM Block")
	}

	return x509.ParseCertificate(block.Bytes)
}

func checkCert(cert *x509.Certificate, publicKey crypto.PublicKey) (err error) {
	pub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return errors.New("certificate verification error")
	}

	return nil
}

func saveCert(storageDir string, cert *x509.Certificate) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*"+crtExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return "", err
	}

	return file.Name(), nil
}

func saveKey(storageDir string, key *rsa.PrivateKey) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*"+keyExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func (module *SWModule) removeCert(cert certhandler.CertInfo) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  cert.CertURL,
		"keyURL":   cert.KeyURL,
		"notAfter": cert.NotAfter}).Debug("Remove certificate")

	if err = module.storage.RemoveCertificate(module.certType, cert.CertURL); err != nil {
		return err
	}

	keyURL, err := url.Parse(cert.KeyURL)
	if err != nil {
		return err
	}

	if err = os.Remove(keyURL.Path); err != nil {
		return err
	}

	certURL, err := url.Parse(cert.CertURL)
	if err != nil {
		return err
	}

	if err = os.Remove(certURL.Path); err != nil {
		return err
	}

	return nil
}

func getFilesByExt(storagePath, ext string) (files []string, err error) {
	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil, err
	}

	for _, item := range content {
		if item.IsDir() {
			continue
		}

		if path.Ext(item.Name()) != ext {
			continue
		}

		files = append(files, path.Join(storagePath, item.Name()))
	}

	return files, nil
}

func fileToURL(file string) (urlStr string) {
	urlVal := url.URL{Scheme: "file", Path: file}

	return urlVal.String()
}

func (module *SWModule) updateStorage() (err error) {
	infos, err := module.storage.GetCertificates(module.certType)
	if err != nil {
		return err
	}

	for _, info := range infos {
		if err = func() (err error) {
			x509Cert, err := getCertByURL(info.CertURL)
			if err != nil {
				return err
			}

			if info.Serial != fmt.Sprintf("%X", x509Cert.SerialNumber) {
				return errors.New("invalid certificate serial number")
			}

			if info.Issuer != base64.StdEncoding.EncodeToString(x509Cert.RawIssuer) {
				return errors.New("invalid certificate issuer")
			}

			key, err := getKeyByURL(info.KeyURL)
			if err != nil {
				return err
			}

			if err = checkCert(x509Cert, key.Public()); err != nil {
				return err
			}

			return nil
		}(); err != nil {
			log.WithFields(log.Fields{"certType": module.certType,
				"certURL": info.CertURL, "keyURL": info.KeyURL}).Errorf("Invalid storage entry: %s", err)

			log.WithFields(log.Fields{"certType": module.certType, "certURL": info.CertURL}).Warn("Remove invalid storage entry")

			if err = module.storage.RemoveCertificate(module.certType, info.CertURL); err != nil {
				return err
			}
		}
	}

	return nil
}

func (module *SWModule) storeCert(x509Cert *x509.Certificate, certURL, keyURL string) (err error) {
	certInfo := certhandler.CertInfo{
		Issuer:   base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
		Serial:   fmt.Sprintf("%X", x509Cert.SerialNumber),
		CertURL:  certURL,
		KeyURL:   keyURL,
		NotAfter: x509Cert.NotAfter,
	}

	if err = module.storage.AddCertificate(module.certType, certInfo); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"certType": module.certType,
		"issuer":   certInfo.Issuer,
		"serial":   certInfo.Serial,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": x509Cert.NotAfter}).Debug("Add certificate")

	return nil
}

func getCertByURL(urlStr string) (x509Cert *x509.Certificate, err error) {
	urlVal, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	certPem, err := ioutil.ReadFile(urlVal.Path)
	if err != nil {
		return nil, err
	}

	return pemToX509Cert(string(certPem))
}

func getKeyByURL(urlStr string) (key *rsa.PrivateKey, err error) {
	urlVal, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	pemKey, err := ioutil.ReadFile(urlVal.Path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemKey)
	if err != nil {
		return nil, err
	}

	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return nil, errors.New("invalid PEM Block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (module *SWModule) updateCerts(files []string) (err error) {
	keyFiles, err := getFilesByExt(module.config.StoragePath, keyExt)
	if err != nil {
		return err
	}

	for _, certFile := range files {
		x509Cert, err := getCertByURL(fileToURL(certFile))
		if err != nil {
			return err
		}

		foundKeyFile := ""

		for _, keyFile := range keyFiles {
			key, err := getKeyByURL(fileToURL(keyFile))
			if err != nil {
				return err
			}

			if err = checkCert(x509Cert, key.Public()); err == nil {
				foundKeyFile = keyFile

				break
			}
		}

		if foundKeyFile != "" {
			log.WithFields(log.Fields{"certType": module.certType, "file": certFile}).Warn("Store valid certificate")

			if err = module.storeCert(x509Cert, fileToURL(certFile), fileToURL(foundKeyFile)); err != nil {
				return err
			}
		} else {
			log.WithFields(log.Fields{"certType": module.certType, "file": certFile}).Warn("Remove invalid certificate")

			if err = os.Remove(certFile); err != nil {
				return err
			}
		}
	}

	return nil
}
