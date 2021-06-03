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
	"container/list"
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const defaultTokenLabel = "aos"

const maxPendingKeys = 16

const (
	CKS_RO_PUBLIC_SESSION = iota
	CKS_RO_USER_FUNCTIONS
	CKS_RW_PUBLIC_SESSION
	CKS_RW_USER_FUNCTIONS
	CKS_RW_SO_FUNCTIONS
)

const (
	envLoginType = "CKTEEC_LOGIN_TYPE"
	envLoginGID  = "CKTEEC_LOGIN_GID"
)

const rsaKeyLength = 2048

/*******************************************************************************
 * Types
 ******************************************************************************/

// PKCS11Module PKCS11 certificate module
type PKCS11Module struct {
	certType    string
	config      moduleConfig
	ctx         *pkcs11.Ctx
	session     pkcs11.SessionHandle
	slotID      uint
	userPIN     string
	tokenLabel  string
	pendingKeys *list.List
}

type moduleConfig struct {
	Library          string   `json:"library"`
	SlotID           *uint    `json:"slotId"`
	SlotIndex        *int     `json:"slotIndex"`
	TokenLabel       string   `json:"tokenLabel"`
	UserPIN          string   `json:"userPin"`
	TEELoginType     string   `json:"teeLoginType"`
	UID              uint32   `json:"uid"`
	GID              uint32   `json:"gid"`
	ModulePathInURL  bool     `json:"ModulePathInURL"`
	ClearHookCmdArgs []string `json:"clearHookCmdArgs"`
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var ctxMutex = sync.Mutex{}
var ctxCount = map[string]int{}

// TEE Client UUID name space identifier (UUIDv4) from linux kernel
// https://github.com/OP-TEE/optee_os/pull/4222
var teeClientUuidNs = uuid.Must(uuid.Parse("58ac9ca0-2086-4683-a1b8-ec4bc08e01b6"))

var ecsdaCurveID = elliptic.P384()

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates ssh module instance
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create PKCS11 module")

	pkcs11Module := &PKCS11Module{certType: certType, pendingKeys: list.New()}

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

	if (pkcs11Module.config.UserPIN == "") == (pkcs11Module.config.TEELoginType == "") {
		return nil, errors.New("either userPin or teeLoginType should be used")
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

	module.pendingKeys = list.New()

	soPIN := password
	userPIN := module.userPIN

	if module.config.TEELoginType != "" {
		soPIN = ""

		if userPIN, err = getTeeUserPIN(module.config.TEELoginType, module.config.UID, module.config.GID); err != nil {
			return err
		}
	}

	log.WithFields(log.Fields{"slotID": module.slotID, "label": module.tokenLabel}).Debug("Init token")

	if err = module.ctx.InitToken(module.slotID, soPIN, module.tokenLabel); err != nil {
		return err
	}

	session, err := module.getSession(false)
	if err != nil {
		return err
	}

	if err = module.ctx.Login(session, pkcs11.CKU_SO, soPIN); err != nil {
		return err
	}
	defer func() {
		err = module.ctx.Logout(session)
	}()

	if module.config.TEELoginType != "" {
		log.WithFields(log.Fields{"pin": userPIN, "session": session}).Debug("Init PIN")
	} else {
		log.WithFields(log.Fields{"session": session}).Debug("Init PIN")
	}

	if err = module.ctx.InitPIN(session, userPIN); err != nil {
		return err
	}

	return nil
}

// Clear clears security storage
func (module *PKCS11Module) Clear() (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	session, err := module.getSession(true)
	if err != nil {
		return err
	}

	module.pendingKeys = list.New()

	objects, err := findObjects(module.ctx, session, []*pkcs11.Attribute{})
	if err != nil {
		return err
	}

	for _, object := range objects {
		if objectErr := object.delete(); objectErr != nil {
			if objectErr != nil {
				log.Errorf("Can't delete object, handle: %d", object.handle)

				if err == nil {
					err = objectErr
				}
			}
		}
	}

	return err
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys
func (module *PKCS11Module) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	session, err := module.getSession(true)
	if err != nil {
		return nil, nil, nil, err
	}

	// find all certificate objects

	certObjs, err := findObjects(module.ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// find all public key objects

	pubKeyObjs, err := findObjects(module.ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// find all private key objects

	privKeyObjs, err := findObjects(module.ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// find valid private key + public key + certificate with same ID

	k := 0

	for i, privKeyObj := range privKeyObjs {
		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Private key found")

		pubKeyIndex, err := findObjectIndexByID(privKeyObj.id, pubKeyObjs)
		if err != nil {
			continue
		}

		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Public key found")

		certIndex, err := findObjectIndexByID(privKeyObj.id, certObjs)
		if err != nil {
			continue
		}

		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Certificate found")

		cert := &pkcs11Certificate{pkcs11Object: *certObjs[certIndex]}

		x509Cert, err := cert.getX509Certificate()
		if err != nil {
			log.WithFields(log.Fields{"id": cert.id}).Errorf("Can't get x509 certificate: %s", err)

			continue
		}

		validInfos = append(validInfos, certhandler.CertInfo{
			Issuer:   base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
			Serial:   fmt.Sprintf("%X", x509Cert.SerialNumber),
			NotAfter: x509Cert.NotAfter,
			CertURL:  module.createURL(module.certType, certObjs[certIndex].id),
			KeyURL:   module.createURL(module.certType, privKeyObj.id),
		})

		privKeyObjs[i], privKeyObjs[k] = privKeyObjs[k], privKeyObj
		k++

		certObjs = append(certObjs[:certIndex], certObjs[certIndex+1:]...)
		pubKeyObjs = append(pubKeyObjs[:pubKeyIndex], pubKeyObjs[pubKeyIndex+1:]...)
	}

	privKeyObjs = privKeyObjs[k:]

	// Fill remaining objects as invalid

	for _, privKeyObj := range privKeyObjs {
		log.WithFields(log.Fields{"id": privKeyObj.id}).Warn("Invalid private key")

		invalidKeys = append(invalidKeys, module.createURL(module.certType, privKeyObj.id))
	}

	for _, pubKeyObj := range pubKeyObjs {
		log.WithFields(log.Fields{"id": pubKeyObj.id}).Warn("Invalid public key")

		invalidKeys = append(invalidKeys, module.createURL(module.certType, pubKeyObj.id))
	}

	for _, certObj := range certObjs {
		log.WithFields(log.Fields{"id": certObj.id}).Warn("Invalid certificate")

		invalidCerts = append(invalidCerts, module.createURL(module.certType, certObj.id))
	}

	// Check certificate chains

	invalidChainCerts, err := checkCertificateChain(module.ctx, session)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range invalidChainCerts {
		log.WithFields(log.Fields{"id": cert.id}).Warn("Invalid chain certificate")

		invalidCerts = append(invalidCerts, module.createURL("", cert.id))
	}

	return validInfos, invalidCerts, invalidKeys, nil
}

// CreateKey creates key pair
func (module *PKCS11Module) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	session, err := module.getSession(true)
	if err != nil {
		return nil, err
	}

	var privateKey privateKey

	id := uuid.New().String()

	switch strings.ToLower(algorithm) {
	case cryptutils.AlgRSA:
		privateKey, err = createRSAKey(module.ctx, session, id, module.certType, rsaKeyLength)

	case cryptutils.AlgECC:
		privateKey, err = createECCKey(module.ctx, session, id, module.certType, ecsdaCurveID)

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err = module.tokenMemInfo(); err != nil {
		return nil, err
	}

	module.pendingKeys.PushBack(privateKey)

	if module.pendingKeys.Len() > maxPendingKeys {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old one")

		module.pendingKeys.Remove(module.pendingKeys.Front())
	}
	return privateKey, err
}

// ApplyCertificate applies certificate
func (module *PKCS11Module) ApplyCertificate(cert []byte) (certInfo certhandler.CertInfo, password string, err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	x509Certs, err := cryptutils.PEMToX509Cert(cert)
	if err != nil {
		return certhandler.CertInfo{}, "", err
	}

	var currentKey privateKey
	var next *list.Element

	for e := module.pendingKeys.Front(); e != nil; e = next {
		next = e.Next()

		key, ok := e.Value.(privateKey)
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
		return certhandler.CertInfo{}, "", errors.New("no corresponding key found")
	}

	if err = currentKey.moveToToken(); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	if _, err = createCertificateChain(module.ctx, module.session, currentKey.getID(), module.certType, x509Certs); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	certInfo.CertURL = module.createURL(module.certType, currentKey.getID())
	certInfo.KeyURL = module.createURL(module.certType, currentKey.getID())
	certInfo.Issuer = base64.StdEncoding.EncodeToString(x509Certs[0].RawIssuer)
	certInfo.Serial = fmt.Sprintf("%X", x509Certs[0].SerialNumber)
	certInfo.NotAfter = x509Certs[0].NotAfter

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certInfo.CertURL,
		"keyURL":   certInfo.KeyURL,
		"notAfter": certInfo.NotAfter,
	}).Debug("Certificate applied")

	if err = module.tokenMemInfo(); err != nil {
		return certhandler.CertInfo{}, "", err
	}

	return certInfo, "", nil
}

// RemoveCertificate removes certificate
func (module *PKCS11Module) RemoveCertificate(certURL, password string) (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{
		"certType": module.certType,
		"certURL":  certURL}).Debug("Remove certificate")

	urlTemplate, err := parseURL(certURL)
	if err != nil {
		return err
	}

	session, err := module.getSession(true)
	if err != nil {
		return err
	}

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}

	certObjs, err := findObjects(module.ctx, session, append(template, urlTemplate...))
	if err != nil {
		return err
	}

	for _, certObj := range certObjs {
		if delErr := certObj.delete(); delErr != nil {
			log.Errorf("Can't delete object, handle: %d", certObj.handle)

			if err == nil {
				err = delErr
			}
		}
	}

	return err
}

// RemoveKey removes key
func (module *PKCS11Module) RemoveKey(keyURL, password string) (err error) {
	ctxMutex.Lock()
	defer ctxMutex.Unlock()

	log.WithFields(log.Fields{
		"certType": module.certType,
		"keyURL":   keyURL}).Debug("Remove key")

	urlTemplate, err := parseURL(keyURL)
	if err != nil {
		return err
	}

	session, err := module.getSession(true)
	if err != nil {
		return err
	}

	privObjs, err := findObjects(module.ctx, session, append([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}, urlTemplate...))
	if err != nil {
		return err
	}

	pubObjs, err := findObjects(module.ctx, session, append([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)}, urlTemplate...))
	if err != nil {
		return err
	}

	for _, obj := range append(privObjs, pubObjs...) {
		if delErr := obj.delete(); delErr != nil {
			log.Errorf("Can't delete object, handle: %d", obj.handle)

			if err == nil {
				err = delErr
			}
		}
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func findObjectIndexByID(id string, objs []*pkcs11Object) (index int, err error) {
	for i, obj := range objs {
		if obj.id == id {
			return i, nil
		}
	}

	return 0, errors.New("object not found")
}

func getTeeUserPIN(loginType string, uid, gid uint32) (userPIN string, err error) {
	switch loginType {
	case "public":
		return loginType, nil

	case "user":
		return fmt.Sprintf("%s:%s", loginType, uuid.NewSHA1(teeClientUuidNs, []byte(fmt.Sprintf("uid=%d", uid)))), nil

	case "group":
		return fmt.Sprintf("%s:%s", loginType, uuid.NewSHA1(teeClientUuidNs, []byte(fmt.Sprintf("gid=%d", gid)))), nil

	default:
		return "", fmt.Errorf("wrong TEE login type: %s", loginType)
	}
}

func setTeeEnvVars(loginType string, gid uint32) (err error) {
	switch loginType {
	case "user", "group", "public":
		if os.Getenv(envLoginType) != loginType {
			log.WithFields(log.Fields{"name": envLoginType, "value": loginType}).Debug("Set environment variable")

			if err = os.Setenv(envLoginType, loginType); err != nil {
				return err
			}
		}

		if loginType == "group" {
			gidStr := strconv.FormatUint(uint64(gid), 32)

			log.WithFields(log.Fields{"name": envLoginGID, "value": gidStr}).Debug("Set environment variable")

			if os.Getenv(envLoginGID) != gidStr {
				if err = os.Setenv(envLoginGID, gidStr); err != nil {
					return err
				}
			}
		}

	default:
		return fmt.Errorf("wrong TEE identity: %s", loginType)
	}

	return nil
}

func parseURL(urlStr string) (template []*pkcs11.Attribute, err error) {
	urlVal, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	opaqueValues, err := url.ParseQuery(urlVal.Opaque)
	if err != nil {
		return nil, err
	}

	for key, value := range opaqueValues {
		switch key {
		case "id":
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, value[0]))

		case "object":
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, value[0]))
		}
	}

	return template, nil
}

func (module *PKCS11Module) createURL(label, id string) (uri string) {
	opaque := fmt.Sprintf("token=%s", module.tokenLabel)

	if label != "" {
		opaque += fmt.Sprintf(";object=%s", label)
	}

	if id != "" {
		opaque += fmt.Sprintf(";id=%s", id)
	}

	query := url.Values{}

	if module.config.ModulePathInURL {
		query.Set("module-path", module.config.Library)
	}

	query.Set("pin-value", module.userPIN)

	pkcs11URL := &url.URL{Scheme: cryptutils.SchemePKCS11, Opaque: opaque, RawQuery: query.Encode()}

	return pkcs11URL.String()
}

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

		if module.config.TEELoginType != "" {
			if err = setTeeEnvVars(module.config.TEELoginType, module.config.GID); err != nil {
				return err
			}
		}

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
	if module.config.TEELoginType != "" {
		return ""
	}

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

func (module *PKCS11Module) tokenMemInfo() (err error) {
	tokenInfo, err := module.ctx.GetTokenInfo(module.slotID)
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"publicMemory":  fmt.Sprintf("%d/%d", tokenInfo.TotalPublicMemory-tokenInfo.FreePublicMemory, tokenInfo.TotalPublicMemory),
		"privateMemory": fmt.Sprintf("%d/%d", tokenInfo.TotalPrivateMemory-tokenInfo.FreePrivateMemory, tokenInfo.TotalPrivateMemory),
	}).Debug("Token mem info")

	return nil
}
