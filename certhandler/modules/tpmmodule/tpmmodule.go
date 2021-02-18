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

package tpmmodule

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/tpmkey"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const tpmPermanentOwnerAuthSet = 0x00000001

const maxPendingKeys = 16

const (
	rsaKeyLength = 2048
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// TPMModule TPM certificate module
type TPMModule struct {
	certType      string
	config        moduleConfig
	device        io.ReadWriteCloser
	primaryHandle tpmutil.Handle

	pendingKeys []tpmkey.TPMKey
}

type moduleConfig struct {
	Device      string `json:"device"`
	StoragePath string `json:"storagePath"`
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage,
	device io.ReadWriteCloser) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create TPM module")

	tpmModule := &TPMModule{certType: certType}

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &tpmModule.config); err != nil {
			return nil, err
		}
	}

	if device == nil {
		if tpmModule.config.Device == "" {
			return nil, errors.New("TPM device should be set")
		}

		if tpmModule.device, err = tpm2.OpenTPM(tpmModule.config.Device); err != nil {
			return nil, err
		}
	} else {
		tpmModule.device = device
	}

	if err = os.MkdirAll(tpmModule.config.StoragePath, 0755); err != nil {
		return nil, err
	}

	if err = tpmModule.flushTransientHandles(); err != nil {
		return nil, err
	}

	return tpmModule, nil
}

// Close closes TPM module
func (module *TPMModule) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close TPM module")

	if module.primaryHandle != 0 {
		if flushErr := tpm2.FlushContext(module.device, module.primaryHandle); flushErr != nil {
			if err == nil {
				err = flushErr
			}
		}
	}

	if module.device != nil {
		if closeErr := module.device.Close(); closeErr != nil {
			if err == nil {
				err = closeErr
			}
		}
	}

	return err
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *TPMModule) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	handles, err := module.getPersistentHandles()
	if err != nil {
		return nil, nil, nil, err
	}

	keyMap := make(map[string]tpmkey.TPMKey)

	for _, handle := range handles {
		key, err := tpmkey.CreateFromPersistent(module.device, handle)
		if err != nil {
			return nil, nil, nil, err
		}

		keyMap[handleToURL(handle)] = key
	}

	content, err := ioutil.ReadDir(module.config.StoragePath)
	if err != nil {
		return nil, nil, nil, err
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
			log.WithFields(log.Fields{"certType": module.certType, "file": absItemPath}).Warn("Unknown file found")

			invalidCerts = append(invalidCerts, fileToURL(absItemPath))

			continue
		}

		keyFound := false

		for keyURL, key := range keyMap {
			if cryptutils.CheckCertificate(x509Certs[0], key) == nil {
				validInfos = append(validInfos, certhandler.CertInfo{
					CertURL:  fileToURL(absItemPath),
					KeyURL:   keyURL,
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
		if _, ok := keyMap[info.KeyURL]; ok {
			delete(keyMap, info.KeyURL)
		}
	}

	for keyURL := range keyMap {
		log.WithFields(log.Fields{
			"certType": module.certType,
			"keyURL":   keyURL}).Warn("Found key without corresponding certificate")

		invalidKeys = append(invalidKeys, keyURL)
	}

	return validInfos, invalidCerts, invalidKeys, nil
}

// SetOwner owns security storage
func (module *TPMModule) SetOwner(password string) (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Set owner")

	ownerSet, err := module.isOwnerSet()
	if err != nil {
		return err
	}

	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
	}

	if ownerSet {
		auth.Auth = []byte(password)
	}

	if err = tpm2.HierarchyChangeAuth(module.device, tpm2.HandleOwner, auth, password); err != nil {
		return err
	}

	return nil
}

// Clear clears security storage
func (module *TPMModule) Clear() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	if err = tpm2.Clear(module.device, tpm2.HandleLockout, tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession}); err != nil {
		return err
	}

	if err = os.RemoveAll(module.config.StoragePath); err != nil {
		return err
	}

	if err = os.MkdirAll(module.config.StoragePath, 0755); err != nil {
		return err
	}

	return nil
}

// CreateKey creates key pair
func (module *TPMModule) CreateKey(password string) (key interface{}, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	newKey, err := module.newKey(password)
	if err != nil {
		return "", err
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
func (module *TPMModule) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	x509Certs, err := cryptutils.PEMToX509Cert(cert)
	if err != nil {
		return certhandler.CertInfo{}, "", nil
	}

	var currentKey tpmkey.TPMKey

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

	persistentHandle, err := module.findEmptyPersistentHandle()
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if err = currentKey.MakePersistent(persistentHandle); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	certInfo.CertURL = fileToURL(certFileName)
	certInfo.KeyURL = handleToURL(persistentHandle)
	certInfo.Issuer = base64.StdEncoding.EncodeToString(x509Certs[0].RawIssuer)
	certInfo.Serial = fmt.Sprintf("%X", x509Certs[0].SerialNumber)
	certInfo.NotAfter = x509Certs[0].NotAfter

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": certInfo.NotAfter,
	}).Debug("Certificate applied")

	return certInfo, currentKey.Password(), nil
}

// RemoveCertificate removes certificate
func (module *TPMModule) RemoveCertificate(certURL, password string) (err error) {
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
func (module *TPMModule) RemoveKey(keyURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL}).Debug("Remove key")

	key, err := url.Parse(keyURL)
	if err != nil {
		return err
	}

	handle, err := strconv.ParseUint(key.Hostname(), 0, 32)
	if err != nil {
		return err
	}

	if err = tpm2.EvictControl(module.device, password, tpm2.HandleOwner, tpmutil.Handle(handle), tpmutil.Handle(handle)); err != nil {
		return err
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (module *TPMModule) isOwnerSet() (result bool, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.TPMAPermanent))
	if err != nil {
		return false, err
	}

	if len(values) == 0 {
		return false, errors.New("wrong prop value")
	}

	prop, ok := values[0].(tpm2.TaggedProperty)
	if !ok {
		return false, errors.New("invalid prop type")
	}

	if prop.Value&tpmPermanentOwnerAuthSet != 0 {
		return true, nil
	}

	return false, nil
}

func createPrimaryKey(device io.ReadWriteCloser, password string) (handle tpmutil.Handle, err error) {
	primaryKeyTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: rsaKeyLength,
		},
	}

	if handle, _, err = tpm2.CreatePrimary(device, tpm2.HandleOwner, tpm2.PCRSelection{},
		password, password, primaryKeyTemplate); err != nil {
		return 0, err
	}

	return handle, nil
}

func (module *TPMModule) newKey(password string) (key tpmkey.TPMKey, err error) {
	if module.primaryHandle == 0 {
		if module.primaryHandle, err = createPrimaryKey(module.device, password); err != nil {
			return nil, err
		}
	}

	keyTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagSign,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: rsaKeyLength,
		},
	}

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(module.device, module.primaryHandle,
		tpm2.PCRSelection{}, password, "", keyTemplate)
	if err != nil {
		return nil, err
	}

	return tpmkey.CreateFromBlobs(module.device, module.primaryHandle, password, privateBlob, publicBlob)
}

func (module *TPMModule) findEmptyPersistentHandle() (handle tpmutil.Handle, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst)+1, uint32(tpm2.PersistentFirst))
	if err != nil {
		return 0, err
	}

	if len(values) == 0 {
		return tpmutil.Handle(tpm2.PersistentFirst), nil
	}

	for i := tpmutil.Handle(tpm2.PersistentFirst); i < tpmutil.Handle(tpm2.PersistentLast); i++ {
		inUse := false

		for _, value := range values {
			handle, ok := value.(tpmutil.Handle)
			if !ok {
				return 0, errors.New("wrong data format")
			}

			if i == handle {
				inUse = true
			}
		}

		if !inUse {
			return i, nil
		}
	}

	return 0, errors.New("no empty persistent slot found")
}

func (module *TPMModule) flushTransientHandles() (err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentFirst)-uint32(tpm2.TransientFirst), uint32(tpm2.TransientFirst))
	if err != nil {
		return err
	}
	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			continue
		}

		if err = tpm2.FlushContext(module.device, handle); err != nil {
			return err
		}
	}

	return nil
}

func fileToURL(file string) (urlStr string) {
	urlVal := url.URL{Scheme: cryptutils.SchemeFile, Path: file}

	return urlVal.String()
}

func handleToURL(handle tpmutil.Handle) (urlStr string) {
	urlVal := url.URL{Scheme: cryptutils.SchemeTPM, Host: fmt.Sprintf("0x%X", handle)}

	return urlVal.String()
}

func (module *TPMModule) getPersistentHandles() (handles []tpmutil.Handle, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
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

func createPEMFile(storageDir string) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*."+cryptutils.PEMExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return file.Name(), err
}
