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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"

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

const maxPendingKeys = 16

const (
	rsaKeyLength = 2048
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// SWModule SW certificate module
type SWModule struct {
	certType string
	config   moduleConfig

	pendingKeys []*rsa.PrivateKey
}

type moduleConfig struct {
	StoragePath string `json:"storagePath"`
}

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create SW module")

	swModule := &SWModule{certType: certType}

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

// SetOwner owns security storage
func (module *SWModule) SetOwner(password string) (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Set owner")

	return nil
}

// Clear clears security storage
func (module *SWModule) Clear() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	if err = os.RemoveAll(module.config.StoragePath); err != nil {
		return err
	}

	if err = os.MkdirAll(module.config.StoragePath, 0755); err != nil {
		return err
	}

	return nil
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *SWModule) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	keyMap := make(map[string]crypto.PublicKey)

	content, err := ioutil.ReadDir(module.config.StoragePath)
	if err != nil {
		return nil, nil, nil, err
	}

	// Collect keys

	for _, item := range content {
		absItemPath := path.Join(module.config.StoragePath, item.Name())

		if item.IsDir() {
			continue
		}

		key, err := getKeyByFileName(absItemPath)
		if err != nil {
			continue
		}

		keyMap[absItemPath] = key.Public()
	}

	for _, item := range content {
		absItemPath := path.Join(module.config.StoragePath, item.Name())

		if item.IsDir() {
			log.WithFields(log.Fields{
				"certType": module.certType,
				"dir":      absItemPath}).Warn("Unexpected dir found in storage, remove it")

			if err = os.RemoveAll(absItemPath); err != nil {
				return nil, nil, nil, err
			}

			continue
		}

		x509Cert, err := getCertByFileName(absItemPath)
		if err != nil {
			if _, ok := keyMap[absItemPath]; !ok {
				log.WithFields(log.Fields{"certType": module.certType, "file": absItemPath}).Warn("Unknown file found")

				invalidCerts = append(invalidCerts, fileToURL(absItemPath))
			}

			continue
		}

		keyFound := false

		for keyFilePath, publicKey := range keyMap {
			if checkCert(x509Cert, publicKey) == nil {
				validInfos = append(validInfos, certhandler.CertInfo{
					CertURL:  fileToURL(absItemPath),
					KeyURL:   fileToURL(keyFilePath),
					Issuer:   base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
					Serial:   fmt.Sprintf("%X", x509Cert.SerialNumber),
					NotAfter: x509Cert.NotAfter,
				})

				keyFound = true

				break
			}
		}

		if !keyFound {
			log.WithFields(log.Fields{
				"certType": module.certType,
				"file":     absItemPath}).Warn("Found certificate without corresponding key")

			invalidCerts = append(invalidCerts, fileToURL(absItemPath))
		}
	}

	for _, info := range validInfos {
		key, err := url.Parse(info.KeyURL)
		if err != nil {
			return nil, nil, nil, err
		}

		if _, ok := keyMap[key.Path]; ok {
			delete(keyMap, key.Path)
		}
	}

	for keyFilePath := range keyMap {
		log.WithFields(log.Fields{
			"certType": module.certType,
			"file":     keyFilePath}).Warn("Found key without corresponding certificate")

		invalidKeys = append(invalidKeys, fileToURL(keyFilePath))
	}

	return validInfos, invalidCerts, invalidKeys, nil
}

// CreateKey creates key pair
func (module *SWModule) CreateKey(password string) (key interface{}, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	newKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if err != nil {
		return nil, err
	}

	if len(module.pendingKeys) < maxPendingKeys {
		module.pendingKeys = append(module.pendingKeys, newKey)
	} else {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old one")

		module.pendingKeys[0] = newKey
	}

	return newKey, nil
}

// ApplyCertificate applies certificate
func (module *SWModule) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	x509Cert, err := pemToX509Cert(cert)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	var currentKey *rsa.PrivateKey

	for i, key := range module.pendingKeys {
		if err = checkCert(x509Cert, key.Public()); err == nil {
			currentKey = key
			module.pendingKeys = append(module.pendingKeys[:i], module.pendingKeys[i+1:]...)

			break
		}
	}

	if currentKey == nil {
		return certhandler.CertInfo{}, "", errors.New("no key found")
	}

	certFileName, err := saveCert(module.config.StoragePath, cert)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	keyFileName, err := saveKey(module.config.StoragePath, currentKey)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	certInfo.CertURL = fileToURL(certFileName)
	certInfo.KeyURL = fileToURL(keyFileName)
	certInfo.Issuer = base64.StdEncoding.EncodeToString(x509Cert.RawIssuer)
	certInfo.Serial = fmt.Sprintf("%X", x509Cert.SerialNumber)
	certInfo.NotAfter = x509Cert.NotAfter

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": certInfo.NotAfter,
	}).Debug("Certificate applied")

	return certInfo, "", nil
}

// RemoveCertificate removes certificate
func (module *SWModule) RemoveCertificate(certURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certURL}).Debug("Remove certificate")

	cert, err := url.Parse(certURL)
	if err != nil {
		return err
	}

	if err = os.Remove(cert.Path); err != nil {
		return err
	}

	return nil
}

// RemoveKey removes key
func (module *SWModule) RemoveKey(keyURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL}).Debug("Remove key")

	key, err := url.Parse(keyURL)
	if err != nil {
		return err
	}

	if err = os.Remove(key.Path); err != nil {
		return err
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func pemToX509Cert(certPem []byte) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode(certPem)

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

func saveCert(storageDir string, cert []byte) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*"+crtExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err = file.Write(cert); err != nil {
		return "", err
	}

	return file.Name(), err
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

func fileToURL(file string) (urlStr string) {
	urlVal := url.URL{Scheme: "file", Path: file}

	return urlVal.String()
}

func getCertByFileName(fileName string) (x509Cert *x509.Certificate, err error) {
	certPem, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return pemToX509Cert(certPem)
}

func getKeyByFileName(fileName string) (key *rsa.PrivateKey, err error) {
	pemKey, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemKey)
	if err != nil {
		return nil, err
	}

	if block == nil {
		return nil, errors.New("invalid PEM Block")
	}

	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return nil, errors.New("invalid PEM Block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
