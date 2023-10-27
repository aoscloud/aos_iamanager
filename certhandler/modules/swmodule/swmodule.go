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

package swmodule

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/certhandler"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const maxPendingKeys = 16

const (
	rsaKeyLength = 2048
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// SWModule SW certificate module.
type SWModule struct {
	certType string
	config   moduleConfig

	pendingKeys *list.List
}

type moduleConfig struct {
	StoragePath string `json:"storagePath"`
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var ecsdaCurveID = elliptic.P384() //nolint:gochecknoglobals // use as constant

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates ssh module instance.
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create SW module")

	swModule := &SWModule{certType: certType, pendingKeys: list.New()}

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &swModule.config); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	if err = os.MkdirAll(swModule.config.StoragePath, 0o755); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return swModule, nil
}

// Close closes SW module.
func (module *SWModule) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close SW module")

	return aoserrors.Wrap(err)
}

// SetOwner owns security storage.
func (module *SWModule) SetOwner(password string) (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Set owner")

	return nil
}

// Clear clears security storage.
func (module *SWModule) Clear() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	if err = os.RemoveAll(module.config.StoragePath); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.MkdirAll(module.config.StoragePath, 0o755); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys.
func (module *SWModule) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error,
) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	keyMap := make(map[string]crypto.PrivateKey)

	content, err := os.ReadDir(module.config.StoragePath)
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	// Collect keys

	for _, item := range content {
		absItemPath := path.Join(module.config.StoragePath, item.Name())

		if item.IsDir() {
			continue
		}

		if key, err := cryptutils.LoadPrivateKeyFromFile(absItemPath); err == nil {
			keyMap[absItemPath] = key
		}
	}

	for _, item := range content {
		absItemPath := path.Join(module.config.StoragePath, item.Name())

		if item.IsDir() {
			log.WithFields(log.Fields{
				"certType": module.certType,
				"dir":      absItemPath,
			}).Warn("Unexpected dir found in storage, remove it")

			if err = os.RemoveAll(absItemPath); err != nil {
				return nil, nil, nil, aoserrors.Wrap(err)
			}

			continue
		}

		x509Certs, err := cryptutils.LoadCertificateFromFile(absItemPath)
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
				"file":     absItemPath,
			}).Warn("Found certificate without corresponding key")

			invalidCerts = append(invalidCerts, fileToURL(absItemPath))
		}
	}

	for _, info := range validInfos {
		if key, err := url.Parse(info.KeyURL); err != nil {
			return nil, nil, nil, aoserrors.Wrap(err)
		} else {
			delete(keyMap, key.Path)
		}
	}

	for keyFilePath := range keyMap {
		log.WithFields(log.Fields{
			"certType": module.certType,
			"file":     keyFilePath,
		}).Warn("Found key without corresponding certificate")

		invalidKeys = append(invalidKeys, fileToURL(keyFilePath))
	}

	return validInfos, invalidCerts, invalidKeys, nil
}

// CreateKey creates key pair.
func (module *SWModule) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	switch strings.ToLower(algorithm) {
	case cryptutils.AlgRSA:
		if key, err = rsa.GenerateKey(rand.Reader, rsaKeyLength); err != nil {
			return nil, aoserrors.Wrap(err)
		}

	case cryptutils.AlgECC:
		if key, err = ecdsa.GenerateKey(ecsdaCurveID, rand.Reader); err != nil {
			return nil, aoserrors.Wrap(err)
		}

	default:
		return nil, aoserrors.Errorf("unsupported algorithm: %s", algorithm)
	}

	module.pendingKeys.PushBack(key)

	if module.pendingKeys.Len() > maxPendingKeys {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old one")

		module.pendingKeys.Remove(module.pendingKeys.Front())
	}

	return key, nil
}

// ApplyCertificate applies certificate.
func (module *SWModule) ApplyCertificate(x509Certs []*x509.Certificate) (
	certInfo certhandler.CertInfo, password string, err error,
) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	var (
		currentKey crypto.PrivateKey
		next       *list.Element
	)

	for e := module.pendingKeys.Front(); e != nil; e = next {
		next = e.Next()

		key, ok := e.Value.(crypto.PrivateKey)
		if !ok {
			log.Errorf("Wrong key type in pending keys list")

			continue
		}

		if cryptutils.CheckCertificate(x509Certs[0], key) == nil {
			currentKey = key

			module.pendingKeys.Remove(e)

			break
		}
	}

	if currentKey == nil {
		return certhandler.CertInfo{}, "", aoserrors.New("no key found")
	}

	certFileName, err := createPEMFile(module.config.StoragePath)
	if err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	if err = cryptutils.SaveCertificateToFile(certFileName, x509Certs); err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	keyFileName, err := createPEMFile(module.config.StoragePath)
	if err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	if err = cryptutils.SavePrivateKeyToFile(keyFileName, currentKey); err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
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

// RemoveCertificate removes certificate.
func (module *SWModule) RemoveCertificate(certURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certURL,
	}).Debug("Remove certificate")

	cert, err := url.Parse(certURL)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.Remove(cert.Path); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// RemoveKey removes key.
func (module *SWModule) RemoveKey(keyURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL,
	}).Debug("Remove key")

	key, err := url.Parse(keyURL)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.Remove(key.Path); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func fileToURL(file string) (urlStr string) {
	urlVal := url.URL{Scheme: cryptutils.SchemeFile, Path: file}

	return urlVal.String()
}

func createPEMFile(storageDir string) (fileName string, err error) {
	file, err := os.CreateTemp(storageDir, "*."+cryptutils.PEMExt)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}
	defer file.Close()

	return file.Name(), aoserrors.Wrap(err)
}
