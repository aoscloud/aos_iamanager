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

package certhandler

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	clientAuth = "clientauth"
	serverAuth = "serverauth"
)

const csrBlockType = "CERTIFICATE REQUEST"

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
	SyncStorage() (err error)
	SetOwner(password string) (err error)
	Clear() (err error)
	CreateKey(password string) (key interface{}, err error)
	ApplyCertificate(cert string) (certInfo CertInfo, password string, err error)
	RemoveCertificate(certURL, keyURL, password string) (err error)
	Close() (err error)
}

// NewPlugin plugin new function
type NewPlugin func(certType string, configJSON json.RawMessage, storage CertStorage) (module CertModule, err error)

type moduleDescriptor struct {
	config config.ModuleConfig
	module CertModule
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
			return nil, err
		}

		handler.moduleDescriptors[moduleCfg.ID] = descriptor
	}

	if err = handler.syncStorage(); err != nil {
		return nil, err
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
		return fmt.Errorf("module %s not found", certType)
	}

	return descriptor.module.SetOwner(password)
}

// Clear clears security storage
func (handler *Handler) Clear(certType string) (err error) {
	handler.Lock()
	defer handler.Unlock()

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return fmt.Errorf("module %s not found", certType)
	}

	if err = descriptor.module.Clear(); err != nil {
		return err
	}

	return handler.storage.RemoveAllCertificates(certType)
}

// CreateKey creates key pair
func (handler *Handler) CreateKey(certType, password string) (csr []byte, err error) {
	handler.Lock()
	defer handler.Unlock()

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return nil, fmt.Errorf("module %s not found", certType)
	}

	key, err := descriptor.module.CreateKey(password)
	if err != nil {
		return nil, err
	}

	csrData, err := createCSR(handler.systemID, descriptor.config.ExtendedKeyUsage, descriptor.config.AlternativeNames, key)
	if err != nil {
		return nil, err
	}

	return csrData, nil
}

// ApplyCertificate applies certificate
func (handler *Handler) ApplyCertificate(certType string, cert string) (certURL string, err error) {
	handler.Lock()
	defer handler.Unlock()

	descriptor, ok := handler.moduleDescriptors[certType]
	if !ok {
		return "", fmt.Errorf("module %s not found", certType)
	}

	certInfo, password, err := descriptor.module.ApplyCertificate(cert)
	if err != nil {
		return "", err
	}

	certURL = certInfo.CertURL

	if err = handler.storage.AddCertificate(certType, certInfo); err != nil {
		return "", err
	}

	certs, err := handler.storage.GetCertificates(certType)
	if err != nil {
		log.Errorf("Can' get certificates: %s", err)
	}

	for len(certs) > descriptor.config.MaxItems && descriptor.config.MaxItems != 0 {
		log.Warnf("Current cert count exceeds max count: %d > %d. Remove old certificates",
			len(certs), descriptor.config.MaxItems)

		var minTime time.Time
		var minIndex int

		for i, cert := range certs {
			if minTime.IsZero() || cert.NotAfter.Before(minTime) {
				minTime = cert.NotAfter
				minIndex = i
			}
		}

		if err = descriptor.module.RemoveCertificate(
			certs[minIndex].CertURL, certs[minIndex].KeyURL, password); err != nil {
			return "", err
		}

		if err = handler.storage.RemoveCertificate(certType, certs[minIndex].CertURL); err != nil {
			return "", err
		}

		certs = append(certs[:minIndex], certs[minIndex+1:]...)
	}

	return certURL, nil
}

// GetCertificate returns certificate info
func (handler *Handler) GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error) {
	handler.Lock()
	defer handler.Unlock()

	if serial == "" {
		certInfos, err := handler.storage.GetCertificates(certType)
		if err != nil {
			return "", "", err
		}

		if len(certInfos) == 0 {
			return "", "", errors.New("certificate not found")
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
		return "", "", err
	}

	return certInfo.CertURL, certInfo.KeyURL, nil
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

func createCSR(systemID string, extendedKeyUsage, alternativeNames []string, key interface{}) (csr []byte, err error) {
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
			return nil, err
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    oidExtensionExtendedKeyUsage,
			Value: oidsValue})
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: csrBlockType, Bytes: csrDER}), nil
}

func (handler *Handler) createModule(cfg config.ModuleConfig) (descriptor moduleDescriptor, err error) {
	newFunc, ok := plugins[cfg.Plugin]
	if !ok {
		return moduleDescriptor{}, fmt.Errorf("plugin %s not found", cfg.Plugin)
	}

	if descriptor.module, err = newFunc(cfg.ID, cfg.Params, handler.storage); err != nil {
		return moduleDescriptor{}, err
	}

	descriptor.config = cfg

	return descriptor, nil
}

func (handler *Handler) syncStorage() (err error) {
	handler.Lock()
	defer handler.Unlock()

	log.Debug("Sync certificate DB")

	for _, descriptor := range handler.moduleDescriptors {
		if err = descriptor.module.SyncStorage(); err != nil {
			return err
		}
	}

	return nil
}
