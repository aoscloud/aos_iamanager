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
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const defaultTokenLabel = "aos"

const (
	CKS_RO_PUBLIC_SESSION = iota
	CKS_RO_USER_FUNCTIONS
	CKS_RW_PUBLIC_SESSION
	CKS_RW_USER_FUNCTIONS
	CKS_RW_SO_FUNCTIONS
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// PKCS11Module PKCS11 certificate module
type PKCS11Module struct {
	certType   string
	config     moduleConfig
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	slotID     uint
	userPIN    string
	tokenLabel string
}

type moduleConfig struct {
	Library          string   `json:"library"`
	SlotID           *uint    `json:"slotId"`
	SlotIndex        *int     `json:"slotIndex"`
	TokenLabel       string   `json:"tokenLabel"`
	UserPIN          string   `json:"userPin"`
	ClearHookCmdArgs []string `json:"clearHookCmdArgs"`
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var ctxMutex = sync.Mutex{}
var ctxCount = map[string]int{}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create PKCS11 module")

	pkcs11Module := &PKCS11Module{certType: certType}

	defer func() {
		if err != nil {
			pkcs11Module.Close()
		}
	}()

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &pkcs11Module.config); err != nil {
			return nil, err
		}
	}

	if err = pkcs11Module.initContext(); err != nil {
		return nil, err
	}

	if err = pkcs11Module.displayInfo(pkcs11Module.slotID); err != nil {
		return nil, err
	}

	return pkcs11Module, nil
}

// Close closes PKCS11 module
func (module *PKCS11Module) Close() (err error) {
	log.WithField("certType", module.certType).Info("Close PKCS11 module")

	if sessionErr := module.releaseSession(); sessionErr != nil {
		if err == nil {
			err = sessionErr
		}
	}

	if ctxErr := module.releaseContext(); ctxErr != nil {
		if err == nil {
			err = ctxErr
		}
	}

	return err
}

// SetOwner owns slot
func (module *PKCS11Module) SetOwner(password string) (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType, "slotID": module.slotID}).Debug("Set owner")
	log.WithFields(log.Fields{"slotID": module.slotID}).Debug("Close all sessions")

	if err = module.ctx.CloseAllSessions(module.slotID); err != nil {
		return err
	}

	log.WithFields(log.Fields{"slotID": module.slotID, "label": module.tokenLabel}).Debug("Init token")

	if err = module.ctx.InitToken(module.slotID, password, module.tokenLabel); err != nil {
		return err
	}

	session, err := module.getSession(false)
	if err != nil {
		return err
	}

	if err = module.ctx.Login(session, pkcs11.CKU_SO, password); err != nil {
		return err
	}
	defer func() {
		err = module.ctx.Logout(session)
	}()

	log.WithFields(log.Fields{"session": session}).Debug("Init PIN")

	if err = module.ctx.InitPIN(session, module.userPIN); err != nil {
		return err
	}

	return nil
}

// Clear clears security storage
func (module *PKCS11Module) Clear() (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	return nil
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *PKCS11Module) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	return validInfos, invalidCerts, invalidKeys, nil
}

// CreateKey creates key pair
func (module *PKCS11Module) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	return key, nil
}

// ApplyCertificate applies certificate
func (module *PKCS11Module) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

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
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certURL}).Debug("Remove certificate")

	return nil
}

// RemoveKey removes key
func (module *PKCS11Module) RemoveKey(keyURL, password string) (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL}).Debug("Remove key")

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (module *PKCS11Module) initContext() (err error) {
	module.ctx = pkcs11.New(module.config.Library)

	if module.ctx == nil {
		return fmt.Errorf("can't open PKCS11 library: %s", module.config.Library)
	}

	// PKCS11 lib can be initialized only once per application handle multiple instances
	// with ctxMutex and ctxCount

	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	count := ctxCount[module.config.Library]

	if count == 0 {
		log.WithField("library", module.config.Library).Debug("Initialize PKCS11 library")

		if err = module.ctx.Initialize(); err != nil {
			return err
		}
	}

	ctxCount[module.config.Library] = count + 1

	module.tokenLabel = module.getTokenLabel()
	module.userPIN = module.getUserPIN()

	if module.slotID, err = module.getSlotID(); err != nil {
		return err
	}

	return nil
}

func (module *PKCS11Module) releaseContext() (err error) {
	if module.ctx == nil {
		return nil
	}

	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	count := ctxCount[module.config.Library] - 1

	if count == 0 {
		log.WithField("library", module.config.Library).Debug("Finalize PKCS11 library")

		if ctxErr := module.ctx.Finalize(); ctxErr != nil {
			if err == nil {
				err = ctxErr
			}
		}
	}

	if count >= 0 {
		ctxCount[module.config.Library] = count
	} else {
		if err == nil {
			err = errors.New("wrong PKCS11 context count")
		}
	}

	module.ctx.Destroy()

	return err
}

func (module *PKCS11Module) getSession(userLogin bool) (session pkcs11.SessionHandle, err error) {
	session = module.session

	info, err := module.ctx.GetSessionInfo(module.session)
	if err != nil {
		pkcs11Err, ok := err.(pkcs11.Error)

		if !ok || uint(pkcs11Err) != pkcs11.CKR_SESSION_HANDLE_INVALID {
			return 0, err
		}

		if session, err = module.ctx.OpenSession(module.slotID,
			pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION); err != nil {
			return 0, err
		}

		log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("Open session")

		if info, err = module.ctx.GetSessionInfo(session); err != nil {
			return 0, err
		}
	}

	isUserLoggedIn := info.State == CKS_RO_USER_FUNCTIONS || info.State == CKS_RW_USER_FUNCTIONS
	isSOLoggedIn := info.State == CKS_RW_SO_FUNCTIONS

	if isSOLoggedIn {
		if err = module.ctx.Logout(session); err != nil {
			return 0, err
		}
	}

	if userLogin && !isUserLoggedIn {
		log.WithFields(log.Fields{"session": session, "slotID": module.slotID, "userPin": module.userPIN}).Debug("User login")

		if err = module.ctx.Login(session, pkcs11.CKU_USER, module.userPIN); err != nil {
			pkcs11Err, ok := err.(pkcs11.Error)

			if !ok || pkcs11Err != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				return 0, err
			}
		}
	}

	if !userLogin && isUserLoggedIn {
		log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("User logout")

		if err = module.ctx.Logout(session); err != nil {
			pkcs11Err, ok := err.(pkcs11.Error)

			if !ok || pkcs11Err != pkcs11.CKR_USER_NOT_LOGGED_IN {
				return 0, err
			}
		}
	}

	module.session = session

	return session, nil
}

func (module *PKCS11Module) releaseSession() (err error) {
	if module.session != 0 {
		log.WithFields(log.Fields{"session": module.session, "slotID": module.slotID}).Debug("Close session")

		if err = module.ctx.CloseSession(module.session); err != nil {
			pkcs11Err, ok := err.(pkcs11.Error)

			if !ok || uint(pkcs11Err) != pkcs11.CKR_SESSION_HANDLE_INVALID {
				return err
			}
		}
	}

	return nil
}

func (module *PKCS11Module) getUserPIN() (pin string) {
	return module.config.UserPIN
}

func (module *PKCS11Module) getTokenLabel() (label string) {
	if module.config.TokenLabel != "" {
		return module.config.TokenLabel
	}

	return defaultTokenLabel
}

func (module *PKCS11Module) getSlotID() (id uint, err error) {
	// Find our slot either by slotId or by slot index or by tokenLabel
	// If neither one is specified try to find slot by default token label.
	// If slot is not found, try to find first free slot.

	paramCount := 0

	if module.config.SlotID != nil {
		paramCount++
	}

	if module.config.SlotIndex != nil {
		paramCount++
	}

	if module.config.TokenLabel != "" {
		paramCount++
	}

	if paramCount >= 2 {
		return 0, errors.New("only one parameter for slot identification should be specified (slotId or slotIndex or tokenLabel)")
	}

	if module.config.SlotID != nil {
		return *module.config.SlotID, nil
	}

	slotIDs, err := module.ctx.GetSlotList(false)
	if err != nil {
		return 0, err
	}

	if module.config.SlotIndex != nil {
		if *module.config.SlotIndex >= len(slotIDs) || *module.config.SlotIndex < 0 {
			return 0, errors.New("invalid slot index")
		}

		return slotIDs[*module.config.SlotIndex], nil
	}

	var (
		freeID    uint
		freeFound bool
	)

	for _, id := range slotIDs {
		slotInfo, err := module.ctx.GetSlotInfo(id)
		if err != nil {
			return 0, err
		}

		if slotInfo.Flags&pkcs11.CKF_TOKEN_PRESENT != 0 {
			tokenInfo, err := module.ctx.GetTokenInfo(id)
			if err != nil {
				return 0, err
			}

			if tokenInfo.Label == module.tokenLabel {
				return id, nil
			}

			if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 && !freeFound {
				freeID = id
				freeFound = true
			}
		}
	}

	if freeFound {
		return freeID, nil
	}

	return 0, errors.New("no suitable slot found")
}

func (module *PKCS11Module) displayInfo(slotID uint) (err error) {
	libInfo, err := module.ctx.GetInfo()
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"library":         module.config.Library,
		"cryptokiVersion": fmt.Sprintf("%d.%d", libInfo.CryptokiVersion.Major, libInfo.CryptokiVersion.Minor),
		"manufacturer":    libInfo.ManufacturerID,
		"description":     libInfo.LibraryDescription,
		"libraryVersion":  fmt.Sprintf("%d.%d", libInfo.LibraryVersion.Major, libInfo.LibraryVersion.Minor),
	}).Debug("Library info")

	slotInfo, err := module.ctx.GetSlotInfo(slotID)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"slotID":       slotID,
		"manufacturer": slotInfo.ManufacturerID,
		"description":  slotInfo.SlotDescription,
		"hwVersion":    fmt.Sprintf("%d.%d", slotInfo.HardwareVersion.Major, slotInfo.HardwareVersion.Major),
		"fwVersion":    fmt.Sprintf("%d.%d", slotInfo.FirmwareVersion.Major, slotInfo.FirmwareVersion.Major),
	}).Debug("Slot info")

	tokenInfo, err := module.ctx.GetTokenInfo(slotID)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"slotID":        slotID,
		"label":         tokenInfo.Label,
		"manufacturer":  tokenInfo.ManufacturerID,
		"model":         tokenInfo.Model,
		"serial":        tokenInfo.SerialNumber,
		"hwVersion":     fmt.Sprintf("%d.%d", tokenInfo.HardwareVersion.Major, tokenInfo.HardwareVersion.Major),
		"fwVersion":     fmt.Sprintf("%d.%d", tokenInfo.FirmwareVersion.Major, tokenInfo.FirmwareVersion.Major),
		"publicMemory":  fmt.Sprintf("%d/%d", tokenInfo.TotalPublicMemory-tokenInfo.FreePublicMemory, tokenInfo.TotalPublicMemory),
		"privateMemory": fmt.Sprintf("%d/%d", tokenInfo.TotalPrivateMemory-tokenInfo.FreePrivateMemory, tokenInfo.TotalPrivateMemory),
	}).Debug("Token info")

	return nil
}
