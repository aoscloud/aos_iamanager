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

package certhandler

import (
	"aos_iamanager/config"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	log "github.com/sirupsen/logrus"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	clientAuth = "clientauth"
	serverAuth = "serverauth"
)

const selfSignedCertValidPeriod = time.Hour * 24 * 365 * 100

/*******************************************************************************
 * Vars
 ******************************************************************************/

var (
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtKeyUsageServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

var plugins = make(map[string]NewPlugin)

/*******************************************************************************
 * Types
 ******************************************************************************/

// Handler update handler
type Handler struct {
	sync.Mutex

	systemID          string
	storage           CertStorage
	moduleDescriptors map[string]moduleDescriptor
}

// CertInfo certificate info
type CertInfo struct {
	Issuer   string
	Serial   string
	CertURL  string
	KeyURL   string
	NotAfter time.Time
}

// CertStorage provides API to store/retreive certificates info
type CertStorage interface {
	AddCertificate(certType string, cert CertInfo) (err error)
	GetCertificate(issuer, serial string) (cert CertInfo, err error)
	GetCertificates(certType string) (certs []CertInfo, err error)
	RemoveCertificate(certType, certURL string) (err error)
	RemoveAllCertificates(certType string) (err error)
}

// CertModule provides API to manage module certificates
type CertModule interface {
	ValidateCertificates() (validInfos []CertInfo, invalidCerts, invalidKeys []string, err error)
	SetOwner(password string) (err error)
	Clear() (err error)
	CreateKey(password, algorithm string) (key crypto.PrivateKey, err error)
	ApplyCertificate(certs []*x509.Certificate) (certInfo CertInfo, password string, err error)
	RemoveCertificate(certURL, password string) (err error)
	RemoveKey(certURL, password string) (err error)
	Close() (err error)
}

// NewPlugin plugin new function
type NewPlugin func(certType string, configJSON json.RawMessage) (module CertModule, err error)

type moduleDescriptor struct {
	config       config.ModuleConfig
	invalidCerts []string
	invalidKeys  []string
	module       CertModule
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// RegisterPlugin registers module plugin
func RegisterPlugin(plugin string, newFunc NewPlugin) {
	log.WithField("plugin", plugin).Info("Register certificate plugin")

	plugins[plugin] = newFunc
}

// New returns pointer to new Handler
func New(systemID string, cfg *config.Config, storage CertStorage) (handler *Handler, err error) {
	handler = &Handler{systemID: systemID, moduleDescriptors: make(map[string]moduleDescriptor), storage: storage}

	log.Debug("Create certificate handler")

	for _, moduleCfg := range cfg.CertModules {
		if moduleCfg.Disabled {
			log.WithField("id", moduleCfg.ID).Debug("Skip disabled certificate module")

			continue
		}

		descriptor, err := handler.createModule(moduleCfg)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		handler.moduleDescriptors[moduleCfg.ID] = descriptor
	}

	if err = handler.syncStorage(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return handler, nil
}

// GetCertTypes returns IAM cert types
func (handler *Handler) GetCertTypes() (certTypes []string) {
	handler.Lock()
	defer handler.Unlock()

	certTypes = make([]string, 0, len(handler.moduleDescriptors))

	for certType := range handler.moduleDescriptors {
		certTypes = append(certTypes, certType)
	}

	return certTypes
}

// SetOwner owns security storage
func (handler *Handler) SetOwner(certType, password string) (err error) {
	handler.Lock()
	defer handler.Unlock()

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return aoserrors.Errorf("module %s not found", certType)
	}

	return aoserrors.Wrap(descriptor.module.SetOwner(password))
}

// Clear clears security storage
func (handler *Handler) Clear(certType string) (err error) {
	handler.Lock()
	defer handler.Unlock()

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return aoserrors.Errorf("module %s not found", certType)
	}

	if err = descriptor.module.Clear(); err != nil {
		return aoserrors.Wrap(err)
	}

	return aoserrors.Wrap(handler.storage.RemoveAllCertificates(certType))
}

// CreateKey creates key pair
func (handler *Handler) CreateKey(certType, password string) (csr []byte, err error) {
	handler.Lock()
	defer handler.Unlock()

	key, err := handler.createPrivateKey(certType, password)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return nil, aoserrors.Errorf("module %s not found", certType)
	}

	csrData, err := createCSR(handler.systemID,
		descriptor.config.ExtendedKeyUsage, descriptor.config.AlternativeNames, key)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return csrData, nil
}

// ApplyCertificate applies certificate
func (handler *Handler) ApplyCertificate(certType string, cert []byte) (certURL string, err error) {
	handler.Lock()
	defer handler.Unlock()

	x509Certs, err := cryptutils.PEMToX509Cert(cert)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	if err = checkX509CertificateChan(x509Certs); err != nil {
		return "", aoserrors.Wrap(err)
	}

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return "", aoserrors.Errorf("module %s not found", certType)
	}

	certInfo, password, err := descriptor.module.ApplyCertificate(x509Certs)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	certURL = certInfo.CertURL

	if err = handler.storage.AddCertificate(certType, certInfo); err != nil {
		return "", aoserrors.Wrap(err)
	}

	certs, err := handler.storage.GetCertificates(certType)
	if err != nil {
		log.Errorf("Can' get certificates: %s", err)
	}

	for len(certs) > descriptor.config.MaxItems && descriptor.config.MaxItems != 0 {
		log.Warnf("Current cert count exceeds max count: %d > %d. Remove old certificates",
			len(certs), descriptor.config.MaxItems)

		var (
			minTime  time.Time
			minIndex int
		)

		for i, cert := range certs {
			if minTime.IsZero() || cert.NotAfter.Before(minTime) {
				minTime = cert.NotAfter
				minIndex = i
			}
		}

		if err = descriptor.module.RemoveCertificate(certs[minIndex].CertURL, password); err != nil {
			return "", aoserrors.Wrap(err)
		}

		if err = descriptor.module.RemoveKey(certs[minIndex].KeyURL, password); err != nil {
			return "", aoserrors.Wrap(err)
		}

		if err = handler.storage.RemoveCertificate(certType, certs[minIndex].CertURL); err != nil {
			return "", aoserrors.Wrap(err)
		}

		certs = append(certs[:minIndex], certs[minIndex+1:]...)
	}

	return certURL, nil
}

// GetCertificate returns certificate info
func (handler *Handler) GetCertificate(
	certType string, issuer []byte, serial string) (certURL, keyURL string, err error) {
	handler.Lock()
	defer handler.Unlock()

	if serial == "" {
		certInfos, err := handler.storage.GetCertificates(certType)
		if err != nil {
			return "", "", aoserrors.Wrap(err)
		}

		if len(certInfos) == 0 {
			return "", "", aoserrors.New("certificate not found")
		}

		var minTime time.Time

		var certInfo CertInfo

		for _, info := range certInfos {
			if minTime.IsZero() || info.NotAfter.Before(minTime) {
				minTime = info.NotAfter
				certInfo = info
			}
		}

		return certInfo.CertURL, certInfo.KeyURL, nil
	}

	certInfo, err := handler.storage.GetCertificate(base64.StdEncoding.EncodeToString(issuer), serial)
	if err != nil {
		return "", "", aoserrors.Wrap(err)
	}

	return certInfo.CertURL, certInfo.KeyURL, nil
}

func (handler *Handler) CreateSelfSignedCert(certType, password string) (err error) {
	handler.Lock()
	defer handler.Unlock()

	key, err := handler.createPrivateKey(certType, password)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(selfSignedCertValidPeriod),
		Subject:      pkix.Name{CommonName: "Aos Core"},
		Issuer:       pkix.Name{CommonName: "Aos Core"},
	}

	privKey, ok := key.(crypto.Signer)
	if !ok {
		return aoserrors.New("x509: certificate private key does not implement crypto.Signer")
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), key)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return aoserrors.Errorf("module %s not found", certType)
	}

	x509Certs, err := cryptutils.PEMToX509Cert(
		pem.EncodeToMemory(&pem.Block{Type: cryptutils.PEMBlockCertificate, Bytes: cert}))
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if _, _, err = descriptor.module.ApplyCertificate(x509Certs); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// Close closes certificate handler
func (handler *Handler) Close() {
	log.Debug("Close certificate handler")

	for _, descriptor := range handler.moduleDescriptors {
		if err := descriptor.module.Close(); err != nil {
			log.Errorf("Error closing module: %s", err)
		}
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func checkX509CertificateChan(certs []*x509.Certificate) (err error) {
	if len(certs) == 0 {
		return aoserrors.New("invalid certificate count")
	}

	for _, cert := range certs {
		log.WithFields(log.Fields{"issuer": cert.Issuer, "subject": cert.Subject}).Debug("Check certificate chain")
	}

	checkCerts := make([]*x509.Certificate, len(certs))
	copy(checkCerts, certs)

	currentIndex := 0

	for {
		currentCert := checkCerts[currentIndex]
		checkCerts = append(checkCerts[:currentIndex], checkCerts[currentIndex+1:]...)
		issuerFound := false

		if len(currentCert.RawIssuer) == 0 || bytes.Equal(currentCert.RawIssuer, currentCert.RawSubject) {
			return nil
		}

		for i, cert := range checkCerts {
			if bytes.Equal(currentCert.RawIssuer, cert.RawSubject) ||
				bytes.Equal(currentCert.AuthorityKeyId, cert.SubjectKeyId) {
				issuerFound = true
				currentIndex = i
			}
		}

		if !issuerFound {
			return aoserrors.Errorf("issuer %s not found", currentCert.Issuer)
		}
	}
}

func createCSR(systemID string, extendedKeyUsage, alternativeNames []string, key crypto.PrivateKey) (
	csr []byte, err error) {
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: systemID},
		DNSNames: alternativeNames,
	}

	var oids []asn1.ObjectIdentifier

	for _, value := range extendedKeyUsage {
		switch strings.ToLower(value) {
		case clientAuth:
			oids = append(oids, oidExtKeyUsageClientAuth)

		case serverAuth:
			oids = append(oids, oidExtKeyUsageServerAuth)

		default:
			log.Warnf("Unexpected extended key usage value: %s", value)
		}
	}

	if len(oids) > 0 {
		oidsValue, err := asn1.Marshal(oids)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    oidExtensionExtendedKeyUsage,
			Value: oidsValue,
		})
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: cryptutils.PEMBlockCertificateRequest, Bytes: csrDER}), nil
}

func (handler *Handler) createModule(cfg config.ModuleConfig) (descriptor moduleDescriptor, err error) {
	newFunc, ok := plugins[cfg.Plugin]
	if !ok {
		return moduleDescriptor{}, aoserrors.Errorf("plugin %s not found", cfg.Plugin)
	}

	if descriptor.module, err = newFunc(cfg.ID, cfg.Params); err != nil {
		return moduleDescriptor{}, aoserrors.Wrap(err)
	}

	descriptor.config = cfg

	if descriptor.config.Algorithm == "" {
		descriptor.config.Algorithm = cryptutils.AlgRSA
	}

	return descriptor, nil
}

func (handler *Handler) syncStorage() (err error) {
	handler.Lock()
	defer handler.Unlock()

	log.Debug("Sync certificate DB")

	for _, descriptor := range handler.moduleDescriptors {
		if descriptor.config.SkipValidation {
			log.WithFields(log.Fields{"certType": descriptor.config.ID}).Warn("Skip validation")

			continue
		}

		validItems, invalidCerts, invalidKeys, err := descriptor.module.ValidateCertificates()
		if err != nil {
			return aoserrors.Wrap(err)
		}

		descriptor.invalidCerts = invalidCerts
		descriptor.invalidKeys = invalidKeys

		existingItems, err := handler.storage.GetCertificates(descriptor.config.ID)
		if err != nil {
			return aoserrors.Wrap(err)
		}

		for _, validItem := range validItems {
			found := false

			for i, existingItem := range existingItems {
				if validItem == existingItem {
					found = true

					existingItems = append(existingItems[:i], existingItems[i+1:]...)

					break
				}
			}

			if !found {
				log.WithFields(log.Fields{
					"certType": descriptor.config.ID,
					"certURL":  validItem.CertURL,
					"keyURL":   validItem.KeyURL,
					"notAfter": validItem.NotAfter,
				}).Warn("Add missing cert to DB")

				if err = handler.storage.AddCertificate(descriptor.config.ID, validItem); err != nil {
					return aoserrors.Wrap(err)
				}
			}
		}

		for _, existingItem := range existingItems {
			log.WithFields(log.Fields{
				"certType": descriptor.config.ID,
				"certURL":  existingItem.CertURL,
				"keyURL":   existingItem.KeyURL,
				"notAfter": existingItem.NotAfter,
			}).Warn("Remove invalid cert from DB")

			if err = handler.storage.RemoveCertificate(descriptor.config.ID, existingItem.CertURL); err != nil {
				return aoserrors.Wrap(err)
			}
		}
	}

	return nil
}

func (handler *Handler) createPrivateKey(certType, password string) (key crypto.PrivateKey, err error) {
	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return nil, aoserrors.Errorf("module %s not found", certType)
	}

	for _, certURL := range descriptor.invalidCerts {
		log.WithFields(log.Fields{"certType": certType, "URL": certURL}).Warn("Remove invalid certificate")

		if err = descriptor.module.RemoveCertificate(certURL, password); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	descriptor.invalidCerts = nil

	for _, keyURL := range descriptor.invalidKeys {
		log.WithFields(log.Fields{"certType": certType, "URL": keyURL}).Warn("Remove invalid key")

		if err = descriptor.module.RemoveKey(keyURL, password); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	descriptor.invalidKeys = nil

	key, err = descriptor.module.CreateKey(password, descriptor.config.Algorithm)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return key, nil
}
