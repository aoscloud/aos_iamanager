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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

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

	pendingKeys []interface{}
}

type moduleConfig struct {
	StoragePath          string   `json:"storagePath"`
	ApplyCertHookCmdArgs []string `json:"applyCertHookCmdArgs"`
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var ecsdaCurveID = elliptic.P384()

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

	keyMap := make(map[string]interface{})

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

		key, err := cryptutils.LoadKey(absItemPath)
		if err != nil {
			continue
		}

		keyMap[absItemPath] = key
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

		x509Certs, err := cryptutils.LoadCertificate(absItemPath)
		if err != nil {
			if _, ok := keyMap[absItemPath]; !ok {
				log.WithFields(log.Fields{"certType": module.certType, "file": absItemPath}).Warn("Unknown file found")

				invalidCerts = append(invalidCerts, fileToURL(absItemPath))
			}

			continue
		}

		keyFound := false

		for keyFilePath, key := range keyMap {
			if cryptutils.CheckCertificate(x509Certs[0], key) == nil {
				validInfos = append(validInfos, certhandler.CertInfo{
					CertURL:  fileToURL(absItemPath),
					KeyURL:   fileToURL(keyFilePath),
					Issuer:   base64.StdEncoding.EncodeToString(x509Certs[0].RawIssuer),
					Serial:   fmt.Sprintf("%X", x509Certs[0].SerialNumber),
					NotAfter: x509Certs[0].NotAfter,
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
func (module *SWModule) CreateKey(password, algorithm string) (key interface{}, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	switch strings.ToLower(algorithm) {
	case cryptutils.AlgRSA:
		if key, err = rsa.GenerateKey(rand.Reader, rsaKeyLength); err != nil {
			return nil, err
		}

	case cryptutils.AlgECC:
		if key, err = ecdsa.GenerateKey(ecsdaCurveID, rand.Reader); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if len(module.pendingKeys) < maxPendingKeys {
		module.pendingKeys = append(module.pendingKeys, key)
	} else {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old one")

		module.pendingKeys[0] = key
	}

	return key, nil
}

// ApplyCertificate applies certificate
func (module *SWModule) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	x509Certs, err := cryptutils.PEMToX509Cert(cert)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	var currentKey interface{}

	for i, key := range module.pendingKeys {
		if err = cryptutils.CheckCertificate(x509Certs[0], key); err == nil {
			currentKey = key
			module.pendingKeys = append(module.pendingKeys[:i], module.pendingKeys[i+1:]...)

			break
		}
	}

	if currentKey == nil {
		return certhandler.CertInfo{}, "", errors.New("no key found")
	}

	certFileName, err := createPEMFile(module.config.StoragePath)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if err = cryptutils.SaveCertificate(certFileName, x509Certs); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	keyFileName, err := createPEMFile(module.config.StoragePath)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if err = cryptutils.SaveKey(keyFileName, currentKey); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if len(module.config.ApplyCertHookCmdArgs) > 0 {
		output, err := exec.Command(module.config.ApplyCertHookCmdArgs[0],
			module.config.ApplyCertHookCmdArgs[1:]...).CombinedOutput()
		if err != nil {
			return certInfo, "", fmt.Errorf("message: %s, err: %s", string(output), err)
		}
	}

	certInfo.CertURL = fileToURL(certFileName)
	certInfo.KeyURL = fileToURL(keyFileName)
	certInfo.Issuer = base64.StdEncoding.EncodeToString(x509Certs[0].RawIssuer)
	certInfo.Serial = fmt.Sprintf("%X", x509Certs[0].SerialNumber)
	certInfo.NotAfter = x509Certs[0].NotAfter

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

func fileToURL(file string) (urlStr string) {
	urlVal := url.URL{Scheme: cryptutils.SchemeFile, Path: file}

	return urlVal.String()
}

func createPEMFile(storageDir string) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*."+cryptutils.PEMExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return file.Name(), err
}
