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

package tpmmodule

import (
	"container/list"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/aoserrors"
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
	ecsdaCurveID = tpm2.CurveNISTP384
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

	pendingKeys *list.List
}

type moduleConfig struct {
	Device              string `json:"device"`
	StoragePath         string `json:"storagePath"`
	LockoutMaxTry       uint32 `json:"lockoutMaxTry"`
	RecoveryTime        uint32 `json:"recoveryTime"`
	LockoutRecoveryTime uint32 `json:"lockoutRecoveryTime"`
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage,
	device io.ReadWriteCloser) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create TPM module")

	tpmModule := &TPMModule{certType: certType, pendingKeys: list.New()}

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &tpmModule.config); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	if device == nil {
		if tpmModule.config.Device == "" {
			return nil, aoserrors.New("TPM device should be set")
		}

		if tpmModule.device, err = tpm2.OpenTPM(tpmModule.config.Device); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	} else {
		tpmModule.device = device
	}

	if err = os.MkdirAll(tpmModule.config.StoragePath, 0755); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if err = tpmModule.flushTransientHandles(); err != nil {
		return nil, aoserrors.Wrap(err)
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

	return aoserrors.Wrap(err)
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *TPMModule) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	handles, err := module.getPersistentHandles()
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	keyMap := make(map[string]tpmkey.TPMKey)

	for _, handle := range handles {
		key, err := tpmkey.CreateFromPersistent(module.device, handle)
		if err != nil {
			return nil, nil, nil, aoserrors.Wrap(err)
		}

		keyMap[handleToURL(handle)] = key
	}

	content, err := ioutil.ReadDir(module.config.StoragePath)
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	for _, item := range content {
		absItemPath := path.Join(module.config.StoragePath, item.Name())

		if item.IsDir() {
			log.WithFields(log.Fields{
				"certType": module.certType,
				"dir":      absItemPath}).Warn("Unexpected dir found in storage, remove it")

			if err = os.RemoveAll(absItemPath); err != nil {
				return nil, nil, nil, aoserrors.Wrap(err)
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
		return aoserrors.Wrap(err)
	}

	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
	}

	if ownerSet {
		auth.Auth = []byte(password)
	}

	if err = tpm2.HierarchyChangeAuth(module.device, tpm2.HandleOwner, auth, password); err != nil {
		return aoserrors.Wrap(err)
	}

	if !ownerSet {
		// If all parameters are zeros, left them default (3, 1000, 1000)
		if module.config.LockoutMaxTry != 0 || module.config.RecoveryTime != 0 || module.config.LockoutRecoveryTime != 0 {
			if err = tpm2.DictionaryAttackParameters(module.device, auth, module.config.LockoutMaxTry, module.config.RecoveryTime, module.config.LockoutRecoveryTime); err != nil {
				return aoserrors.Wrap(err)
			}
		}
	}

	return nil
}

// Clear clears security storage
func (module *TPMModule) Clear() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	if err = tpm2.Clear(module.device, tpm2.HandleLockout, tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession}); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.RemoveAll(module.config.StoragePath); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.MkdirAll(module.config.StoragePath, 0755); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// CreateKey creates key pair
func (module *TPMModule) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	newKey, err := module.newKey(password, algorithm)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	module.pendingKeys.PushBack(newKey)

	if module.pendingKeys.Len() > maxPendingKeys {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old one")

		module.pendingKeys.Remove(module.pendingKeys.Front())
	}

	return newKey, nil
}

// ApplyCertificate applies certificate
func (module *TPMModule) ApplyCertificate(x509Certs []*x509.Certificate) (
	certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	var currentKey tpmkey.TPMKey
	var next *list.Element

	for e := module.pendingKeys.Front(); e != nil; e = next {
		next = e.Next()

		key, ok := e.Value.(tpmkey.TPMKey)
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

	if err = cryptutils.SaveCertificate(certFileName, x509Certs); err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	persistentHandle, err := module.findEmptyPersistentHandle()
	if err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	if err = currentKey.MakePersistent(persistentHandle); err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
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
		return aoserrors.Wrap(err)
	}

	if err = os.Remove(cert.Path); err != nil {
		return aoserrors.Wrap(err)
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
		return aoserrors.Wrap(err)
	}

	handle, err := strconv.ParseUint(key.Hostname(), 0, 32)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if err = tpm2.EvictControl(module.device, password, tpm2.HandleOwner, tpmutil.Handle(handle), tpmutil.Handle(handle)); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (module *TPMModule) isOwnerSet() (result bool, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.TPMAPermanent))
	if err != nil {
		return false, aoserrors.Wrap(err)
	}

	if len(values) == 0 {
		return false, aoserrors.New("wrong prop value")
	}

	prop, ok := values[0].(tpm2.TaggedProperty)
	if !ok {
		return false, aoserrors.New("invalid prop type")
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
		return 0, aoserrors.Wrap(err)
	}

	return handle, nil
}

func (module *TPMModule) newKey(password, algorithm string) (key tpmkey.TPMKey, err error) {
	if module.primaryHandle == 0 {
		if module.primaryHandle, err = createPrimaryKey(module.device, password); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	var keyTemplate tpm2.Public

	switch strings.ToLower(algorithm) {
	case cryptutils.AlgRSA:
		keyTemplate = tpm2.Public{
			Type:    tpm2.AlgRSA,
			NameAlg: tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
				tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagSign,
			RSAParameters: &tpm2.RSAParams{
				KeyBits: rsaKeyLength,
			},
		}

	case cryptutils.AlgECC:
		keyTemplate = tpm2.Public{
			Type:    tpm2.AlgECC,
			NameAlg: tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
				tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagSign,
			ECCParameters: &tpm2.ECCParams{
				CurveID: ecsdaCurveID,
			},
		}

	default:
		return nil, aoserrors.Errorf("unsupported algorithm: %s", algorithm)
	}

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(module.device, module.primaryHandle,
		tpm2.PCRSelection{}, password, "", keyTemplate)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	key, err = tpmkey.CreateFromBlobs(module.device, module.primaryHandle, password, privateBlob, publicBlob)

	return key, aoserrors.Wrap(err)
}

func (module *TPMModule) findEmptyPersistentHandle() (handle tpmutil.Handle, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst)+1, uint32(tpm2.PersistentFirst))
	if err != nil {
		return 0, aoserrors.Wrap(err)
	}

	if len(values) == 0 {
		return tpmutil.Handle(tpm2.PersistentFirst), nil
	}

	for i := tpmutil.Handle(tpm2.PersistentFirst); i < tpmutil.Handle(tpm2.PersistentLast); i++ {
		inUse := false

		for _, value := range values {
			handle, ok := value.(tpmutil.Handle)
			if !ok {
				return 0, aoserrors.New("wrong data format")
			}

			if i == handle {
				inUse = true
			}
		}

		if !inUse {
			return i, nil
		}
	}

	return 0, aoserrors.New("no empty persistent slot found")
}

func (module *TPMModule) flushTransientHandles() (err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentFirst)-uint32(tpm2.TransientFirst), uint32(tpm2.TransientFirst))
	if err != nil {
		return aoserrors.Wrap(err)
	}
	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			continue
		}

		if err = tpm2.FlushContext(module.device, handle); err != nil {
			return aoserrors.Wrap(err)
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
		return nil, aoserrors.Wrap(err)
	}

	for _, value := range values {
		handle, ok := value.(tpmutil.Handle)
		if !ok {
			return nil, aoserrors.New("wrong TPM data format")
		}

		handles = append(handles, handle)
	}

	return handles, nil
}

func createPEMFile(storageDir string) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*."+cryptutils.PEMExt)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}
	defer file.Close()

	return file.Name(), aoserrors.Wrap(err)
}
