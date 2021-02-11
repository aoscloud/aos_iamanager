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
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const tpmPermanentOwnerAuthSet = 0x00000001

/*******************************************************************************
 * Types
 ******************************************************************************/

// TPMModule TPM certificate module
type TPMModule struct {
	certType string
	config   moduleConfig
	device   io.ReadWriteCloser
	storage  certhandler.CertStorage

	currentKey *key
}

type moduleConfig struct {
	Device      string `json:"device"`
	StoragePath string `json:"storagePath"`
	MaxItems    int    `json:"maxItems"`
}

type key struct {
	device    io.ReadWriteCloser
	handle    tpmutil.Handle
	pub       tpm2.Public
	publicKey crypto.PublicKey
	password  string
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
func New(certType string, configJSON json.RawMessage, storage certhandler.CertStorage,
	device io.ReadWriteCloser) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create TPM module")

	tpmModule := &TPMModule{certType: certType, storage: storage}

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

	return tpmModule, nil
}

// Close closes TPM module
func (module *TPMModule) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close TPM module")

	if module.currentKey != nil {
		if flushErr := module.currentKey.flush(); flushErr != nil {
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

// SyncStorage syncs cert storage
func (module *TPMModule) SyncStorage() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Sync storage")

	if err = module.updateStorage(); err != nil {
		return err
	}

	files, err := getCertFiles(module.config.StoragePath)
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

	if err = module.storage.RemoveAllCertificates(module.certType); err != nil {
		return err
	}

	return nil
}

// CreateKey creates key pair
func (module *TPMModule) CreateKey(password string) (key interface{}, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	if module.currentKey != nil {
		log.Warning("Current key exists. Flushing...")

		if err = module.currentKey.flush(); err != nil {
			return nil, err
		}
	}

	if module.currentKey, err = module.newKey(password); err != nil {
		return "", err
	}

	return module.currentKey, nil
}

// ApplyCertificate applies certificate
func (module *TPMModule) ApplyCertificate(cert string) (certURL, keyURL string, err error) {
	if module.currentKey == nil {
		return "", "", errors.New("no key created")
	}
	defer func() { module.currentKey = nil }()

	x509Cert, err := pemToX509Cert(cert)
	if err != nil {
		return "", "", nil
	}

	if err = checkCert(x509Cert, module.currentKey.publicKey); err != nil {
		return "", "", err
	}

	certFileName, err := saveCert(module.config.StoragePath, cert)
	if err != nil {
		return "", "", err
	}

	persistentHandle, err := module.findEmptyPersistentHandle()
	if err != nil {
		return "", "", err
	}

	if err = module.currentKey.makePersistent(persistentHandle); err != nil {
		return "", "", err
	}

	certURL = fileToURL(certFileName)
	keyURL = handleToURL(persistentHandle)

	if err = module.addCertToDB(x509Cert, certURL, keyURL); err != nil {
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

		if err = module.removeCert(certs[minIndex], module.currentKey.password); err != nil {
			log.Errorf("Can't delete old certificate: %s", err)
		}

		certs = append(certs[:minIndex], certs[minIndex+1:]...)
	}

	return certURL, keyURL, nil
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

func (module *TPMModule) newKey(password string) (k *key, err error) {
	k = &key{device: module.device, password: password}

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

	primaryHandle, _, err := tpm2.CreatePrimary(module.device, tpm2.HandleOwner, tpm2.PCRSelection{}, k.password, k.password, primaryKeyTemplate)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(module.device, primaryHandle)

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(module.device, primaryHandle, tpm2.PCRSelection{}, k.password, "", keyTemplate)
	if err != nil {
		return nil, err
	}

	if k.pub, err = tpm2.DecodePublic(publicBlob); err != nil {
		return nil, err
	}

	if k.publicKey, err = k.pub.Key(); err != nil {
		return nil, err
	}

	if k.handle, _, err = tpm2.Load(module.device, primaryHandle, k.password, publicBlob, privateBlob); err != nil {
		return nil, err
	}

	return k, nil
}

func (k *key) flush() (err error) {
	return tpm2.FlushContext(k.device, k.handle)
}

func (k *key) makePersistent(handle tpmutil.Handle) (err error) {
	// Clear slot
	tpm2.EvictControl(k.device, k.password, tpm2.HandleOwner, handle, handle)

	if err = tpm2.EvictControl(k.device, k.password, tpm2.HandleOwner, k.handle, handle); err != nil {
		return err
	}

	k.flush()

	k.handle = handle

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

	sig, err := tpm2.Sign(k.device, k.handle, "", digest, nil, scheme)
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
	file, err := ioutil.TempFile(storageDir, "*.crt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err = file.WriteString(cert); err != nil {
		return "", err
	}

	return file.Name(), nil
}

func (module *TPMModule) updateStorage() (err error) {
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

			key, err := module.getPublicKeyByURL(info.KeyURL)
			if err != nil {
				return err
			}

			if err = checkCert(x509Cert, key); err != nil {
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

func (module *TPMModule) findEmptyPersistentHandle() (handle tpmutil.Handle, err error) {
	values, _, err := tpm2.GetCapability(module.device, tpm2.CapabilityHandles,
		uint32(tpm2.PersistentLast)-uint32(tpm2.PersistentFirst), uint32(tpm2.PersistentFirst))
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

func (module *TPMModule) removeCert(cert certhandler.CertInfo, password string) (err error) {
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

	handle, err := strconv.ParseUint(keyURL.Hostname(), 0, 32)
	if err != nil {
		return err
	}

	if err = tpm2.EvictControl(module.device, password, tpm2.HandleOwner, tpmutil.Handle(handle), tpmutil.Handle(handle)); err != nil {
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

func (module *TPMModule) addCertToDB(x509Cert *x509.Certificate, certURL, keyURL string) (err error) {
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

func (module *TPMModule) updateCerts(files []string) (err error) {
	handles, err := module.getPersistentHandles()
	if err != nil {
		return err
	}

	publicKeys := make(map[string]crypto.PublicKey)

	for _, handle := range handles {
		keyURL := handleToURL(handle)

		publicKey, err := module.getPublicKeyByURL(keyURL)
		if err != nil {
			return err
		}

		publicKeys[keyURL] = publicKey
	}

	for _, certFile := range files {
		x509Cert, err := getCertByURL(fileToURL(certFile))
		if err != nil {
			return err
		}

		certKeyURL := ""

		for keyURL, publicKey := range publicKeys {
			if err = checkCert(x509Cert, publicKey); err == nil {
				certKeyURL = keyURL
			}
		}

		if certKeyURL != "" {
			log.WithFields(log.Fields{"certType": module.certType, "file": certFile}).Warn("Store valid certificate")

			if err = module.addCertToDB(x509Cert, fileToURL(certFile), certKeyURL); err != nil {
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
