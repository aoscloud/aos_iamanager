// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2021 Renesas Inc.
// Copyright 2021 EPAM Systems Inc.
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

package pkcs11module

import (
	"crypto"
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

// PKCS11Module PKCS11 certificate module
type PKCS11Module struct {
	certType string
	config   moduleConfig
}

type moduleConfig struct {
	Library          string   `json:"library"`
	ClearHookCmdArgs []string `json:"clearHookCmdArgs"`
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create PKCS11 module")

	pkcs11Module := &PKCS11Module{certType: certType}

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &pkcs11Module.config); err != nil {
			return nil, err
		}
	}

	return pkcs11Module, nil
}

// Close closes PKCS11 module
func (module *PKCS11Module) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close PKCS11 module")

	return err
}

// SetOwner owns slot
func (module *PKCS11Module) SetOwner(password string) (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Set owner")

	return nil
}

// Clear clears security storage
func (module *PKCS11Module) Clear() (err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	return nil
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *PKCS11Module) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	return validInfos, invalidCerts, invalidKeys, nil
}

// CreateKey creates key pair
func (module *PKCS11Module) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	return key, nil
}

// ApplyCertificate applies certificate
func (module *PKCS11Module) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": certInfo.NotAfter,
	}).Debug("Certificate applied")

	return certInfo, "", nil
}

// RemoveCertificate removes certificate
func (module *PKCS11Module) RemoveCertificate(certURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certURL}).Debug("Remove certificate")

	return nil
}

// RemoveKey removes key
func (module *PKCS11Module) RemoveKey(keyURL, password string) (err error) {
	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL}).Debug("Remove key")

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/
