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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"path"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const tpmPermanentOwnerAuthSet = 0x00000001

const (
	crtExt = ".crt"
)

const maxPendingKeys = 16

/*******************************************************************************
 * Types
 ******************************************************************************/

// TPMModule TPM certificate module
type TPMModule struct {
	certType      string
	config        moduleConfig
	device        io.ReadWriteCloser
	primaryHandle tpmutil.Handle

	pendingKeys []*key
}

type moduleConfig struct {
	Device      string `json:"device"`
	StoragePath string `json:"storagePath"`
}

type key struct {
	device        io.ReadWriteCloser
	primaryHandle tpmutil.Handle
	publicKey     crypto.PublicKey
	privateBlob   []byte
	publicBlob    []byte
	password      string
}

/*******************************************************************************
 * Types
 ******************************************************************************/

var supportedHash = map[crypto.Hash]tpm2.Algorithm{
	crypto.SHA1:   tpm2.AlgSHA1,
	crypto.SHA256: tpm2.AlgSHA256,
	crypto.SHA384: tpm2.AlgSHA384,
	crypto.SHA512: tpm2.AlgSHA512,
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

	keyMap := make(map[string]crypto.PublicKey)

	for _, handle := range handles {
		keyURL := handleToURL(handle)

		publicKey, err := module.getPublicKeyByURL(keyURL)
		if err != nil {
			return nil, nil, nil, err
		}

		keyMap[keyURL] = publicKey
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

		x509Cert, err := getCertByFileName(absItemPath)
		if err != nil {
			if _, ok := keyMap[absItemPath]; !ok {
				log.WithFields(log.Fields{"certType": module.certType, "file": absItemPath}).Warn("Unknown file found")

				invalidCerts = append(invalidCerts, fileToURL(absItemPath))
			}

			continue
		}

		keyFound := false

		for keyURL, publicKey := range keyMap {
			if checkCert(x509Cert, publicKey) == nil {
				validInfos = append(validInfos, certhandler.CertInfo{
					CertURL:  fileToURL(absItemPath),
					KeyURL:   keyURL,
					Issuer:   base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
					Serial:   fmt.Sprintf("%X", x509Cert.SerialNumber),
					NotAfter: x509Cert.NotAfter,
				})

				delete(keyMap, keyURL)

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
func (module *TPMModule) ApplyCertificate(cert string) (certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	x509Cert, err := pemToX509Cert(cert)
	if err != nil {
		return certhandler.CertInfo{}, "", nil
	}

	var currentKey *key

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

	persistentHandle, err := module.findEmptyPersistentHandle()
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if err = currentKey.makePersistent(persistentHandle); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	certInfo.CertURL = fileToURL(certFileName)
	certInfo.KeyURL = handleToURL(persistentHandle)
	certInfo.Issuer = base64.StdEncoding.EncodeToString(x509Cert.RawIssuer)
	certInfo.Serial = fmt.Sprintf("%X", x509Cert.SerialNumber)
	certInfo.NotAfter = x509Cert.NotAfter

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": certInfo.NotAfter,
	}).Debug("Certificate applied")

	return certInfo, currentKey.password, nil
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
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	if handle, _, err = tpm2.CreatePrimary(device, tpm2.HandleOwner, tpm2.PCRSelection{},
		password, password, primaryKeyTemplate); err != nil {
		return 0, err
	}

	return handle, nil
}

func (module *TPMModule) newKey(password string) (k *key, err error) {
	if module.primaryHandle == 0 {
		if module.primaryHandle, err = createPrimaryKey(module.device, password); err != nil {
			return nil, err
		}
	}

	k = &key{device: module.device, password: password, primaryHandle: module.primaryHandle}

	keyTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagSign,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgNull,
				Hash: tpm2.AlgNull,
			},
			KeyBits: 2048,
		},
	}

	if k.privateBlob, k.publicBlob, _, _, _, err = tpm2.CreateKey(module.device, k.primaryHandle,
		tpm2.PCRSelection{}, k.password, "", keyTemplate); err != nil {
		return nil, err
	}

	tpmPublic, err := tpm2.DecodePublic(k.publicBlob)
	if err != nil {
		return nil, err
	}

	if k.publicKey, err = tpmPublic.Key(); err != nil {
		return nil, err
	}

	return k, nil
}

func (k *key) makePersistent(persistentHandle tpmutil.Handle) (err error) {
	keyHandle, _, err := tpm2.Load(k.device, k.primaryHandle, k.password, k.publicBlob, k.privateBlob)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext(k.device, keyHandle)

	// Clear slot
	tpm2.EvictControl(k.device, k.password, tpm2.HandleOwner, persistentHandle, persistentHandle)

	if err = tpm2.EvictControl(k.device, k.password, tpm2.HandleOwner, keyHandle, persistentHandle); err != nil {
		return err
	}

	return nil
}

func (k *key) Public() crypto.PublicKey {
	return k.publicKey
}

func (k *key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	alg := tpm2.AlgRSASSA

	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		if pssOpts.SaltLength != rsa.PSSSaltLengthAuto {
			return nil, fmt.Errorf("salt length must be rsa.PSSSaltLengthAuto")
		}

		alg = tpm2.AlgRSAPSS
	}

	tpmHash, ok := supportedHash[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %v", opts.HashFunc())
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("wrong digest length: got %d, want %d", digest, opts.HashFunc().Size())
	}

	scheme := &tpm2.SigScheme{
		Alg:  alg,
		Hash: tpmHash,
	}

	keyHandle, _, err := tpm2.Load(k.device, k.primaryHandle, k.password, k.publicBlob, k.privateBlob)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(k.device, keyHandle)

	sig, err := tpm2.Sign(k.device, keyHandle, "", digest, nil, scheme)
	if err != nil {
		return nil, err
	}

	switch sig.Alg {
	case tpm2.AlgRSASSA:
		return sig.RSA.Signature, nil

	case tpm2.AlgRSAPSS:
		return sig.RSA.Signature, nil

	case tpm2.AlgECDSA:
		sigStruct := struct{ R, S *big.Int }{sig.ECC.R, sig.ECC.S}

		return asn1.Marshal(sigStruct)

	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}

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

func saveCert(storageDir string, cert string) (fileName string, err error) {
	file, err := ioutil.TempFile(storageDir, "*"+crtExt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err = file.WriteString(cert); err != nil {
		return "", err
	}

	return file.Name(), err
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

func getCertFiles(storagePath string) (files []string, err error) {
	content, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil, err
	}

	for _, item := range content {
		if item.IsDir() {
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

func handleToURL(handle tpmutil.Handle) (urlStr string) {
	urlVal := url.URL{Scheme: "tpm", Host: fmt.Sprintf("0x%X", handle)}

	return urlVal.String()
}

func getCertByFileName(fileName string) (x509Cert *x509.Certificate, err error) {
	certPem, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return pemToX509Cert(string(certPem))
}

func (module *TPMModule) getPublicKeyByURL(urlStr string) (publicKey crypto.PublicKey, err error) {
	urlVal, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	handle, err := strconv.ParseUint(urlVal.Hostname(), 0, 32)
	if err != nil {
		return nil, err
	}

	pubData, _, _, err := tpm2.ReadPublic(module.device, tpmutil.Handle(handle))
	if err != nil {
		return nil, err
	}

	if publicKey, err = pubData.Key(); err != nil {
		return nil, err
	}

	return publicKey, nil
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
