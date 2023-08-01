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

package pkcs11module

import (
	"container/list"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/dchest/uniuri"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/certhandler"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const defaultTokenLabel = "aos"

const maxPendingKeys = 16

//nolint:stylecheck // standard defines
const (
	CKS_RO_PUBLIC_SESSION = iota
	CKS_RO_USER_FUNCTIONS
	CKS_RW_PUBLIC_SESSION
	CKS_RW_USER_FUNCTIONS
	CKS_RW_SO_FUNCTIONS
)

const envLoginType = "CKTEEC_LOGIN_TYPE"

const (
	loginTypeGroup  = "group"
	loginTypeUser   = "user"
	loginTypePublic = "public"
)

const rsaKeyLength = 2048

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// PKCS11Module PKCS11 certificate module.
type PKCS11Module struct {
	sync.Mutex

	certType     string
	config       moduleConfig
	pkcs11Ctx    *crypto11.PKCS11Context
	crypto11Ctx  *crypto11.Context
	slotID       uint
	teeLoginType string
	userPIN      string
	tokenLabel   string
	pendingKeys  *list.List
}

type moduleConfig struct {
	Library          string   `json:"library"`
	SlotID           *uint    `json:"slotId"`
	SlotIndex        *int     `json:"slotIndex"`
	TokenLabel       string   `json:"tokenLabel"`
	UserPINPath      string   `json:"userPinPath"`
	UID              uint32   `json:"uid"`
	GID              uint32   `json:"gid"`
	ModulePathInURL  bool     `json:"modulePathInUrl"`
	ClearHookCmdArgs []string `json:"clearHookCmdArgs"`
}

type pendingKey struct {
	id string
	crypto11.Signer
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// TEE Client UUID name space identifier (UUIDv4) from linux kernel
// https://github.com/OP-TEE/optee_os/pull/4222
// use as constant.
var teeClientUUIDNs = uuid.Must(uuid.Parse("58ac9ca0-2086-4683-a1b8-ec4bc08e01b6")) //nolint:gochecknoglobals

var ecsdaCurveID = elliptic.P384() //nolint:gochecknoglobals

var errNoContext = errors.New("PKCS11 context is not created")

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates pkcs11 module instance.
func New(certType string, configJSON json.RawMessage) (module certhandler.CertModule, err error) {
	log.WithField("certType", certType).Info("Create PKCS11 module")

	pkcs11Module := &PKCS11Module{certType: certType, pendingKeys: list.New(), teeLoginType: os.Getenv(envLoginType)}

	defer func() {
		if err != nil {
			pkcs11Module.Close()
		}
	}()

	if configJSON != nil {
		if err = json.Unmarshal(configJSON, &pkcs11Module.config); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	if (pkcs11Module.config.UserPINPath == "") == (pkcs11Module.teeLoginType == "") {
		return nil, aoserrors.Errorf("either userPinPath or %s evn should be used", envLoginType)
	}

	if pkcs11Module.pkcs11Ctx, err = crypto11.NewPKCS11Context(pkcs11Module.config.Library); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	pkcs11Module.tokenLabel = pkcs11Module.getTokenLabel()

	if pkcs11Module.slotID, err = pkcs11Module.getSlotID(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	owned, err := pkcs11Module.isOwned()
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if owned {
		if err = pkcs11Module.displayInfo(pkcs11Module.slotID); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = pkcs11Module.createCurrentContext(); err != nil {
			log.Errorf("Can't create current context: %s", err)
		}
	} else {
		log.Debug("No owned token found")
	}

	return pkcs11Module, nil
}

// Close closes PKCS11 module.
func (module *PKCS11Module) Close() (err error) {
	module.Lock()
	defer module.Unlock()

	log.WithField("certType", module.certType).Info("Close PKCS11 module")

	if module.pkcs11Ctx != nil {
		if pkcs11CtxErr := module.pkcs11Ctx.Close(); pkcs11CtxErr != nil {
			if err == nil {
				err = aoserrors.Wrap(pkcs11CtxErr)
			}
		}
	}

	if module.crypto11Ctx != nil {
		if crypto11CtxErr := module.crypto11Ctx.Close(); crypto11CtxErr != nil {
			if err == nil {
				err = aoserrors.Wrap(crypto11CtxErr)
			}
		}
	}

	return err
}

// SetOwner owns slot.
func (module *PKCS11Module) SetOwner(password string) (err error) {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType, "slotID": module.slotID}).Debug("Set owner")

	if module.slotID, err = module.getSlotID(); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = module.closeCurrentContext(); err != nil {
		return aoserrors.Wrap(err)
	}

	var userPIN string

	if module.teeLoginType != "" {
		password = ""

		if userPIN, err = getTeeUserPIN(module.teeLoginType, module.config.UID, module.config.GID); err != nil {
			return aoserrors.Wrap(err)
		}
	} else {
		if userPIN, err = module.getUserPIN(); err != nil {
			userPIN = uniuri.New()

			if err = os.WriteFile(module.config.UserPINPath, []byte(userPIN), 0o600); err != nil {
				return aoserrors.Wrap(err)
			}
		}
	}

	log.WithFields(log.Fields{"slotID": module.slotID, "label": module.tokenLabel}).Debug("Init token")

	if err = module.pkcs11Ctx.InitToken(module.slotID, password, module.tokenLabel); err != nil {
		return aoserrors.Wrap(err)
	}

	session, err := module.createSession(false, password)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	defer func() {
		if releaseErr := aoserrors.Wrap(module.closeSession(session)); releaseErr != nil {
			if err == nil {
				err = releaseErr
			}
		}

		if err != nil {
			return
		}

		if contextErr := module.createCurrentContext(); contextErr != nil {
			if err == nil {
				err = contextErr
			}
		}
	}()

	if module.teeLoginType != "" {
		log.WithFields(log.Fields{"pin": userPIN, "session": session}).Debug("Init PIN")
	} else {
		log.WithFields(log.Fields{"session": session}).Debug("Init PIN")
	}

	if err = module.pkcs11Ctx.InitPIN(session, userPIN); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// Clear clears security storage.
func (module *PKCS11Module) Clear() error {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Clear")

	owned, err := module.isOwned()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if !owned {
		return nil
	}

	if err = module.closeCurrentContext(); err != nil {
		return aoserrors.Wrap(err)
	}

	session, err := module.createSession(true, module.userPIN)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	defer func() {
		if releaseErr := aoserrors.Wrap(module.closeSession(session)); releaseErr != nil {
			if err == nil {
				err = releaseErr
			}
		}
	}()

	objects, err := findObjects(module.pkcs11Ctx, session, []*pkcs11.Attribute{})
	if err != nil {
		return aoserrors.Wrap(err)
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

	return aoserrors.Wrap(err)
}

// ValidateCertificates returns list of valid pairs, invalid certificates and invalid keys.
func (module *PKCS11Module) ValidateCertificates() (
	validInfos []certhandler.CertInfo, invalidCerts, invalidKeys []string, err error,
) {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Validate certificates")

	if owned, err := module.isOwned(); err != nil || !owned {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	session, err := module.createSession(true, module.userPIN)
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	defer func() {
		if releaseErr := aoserrors.Wrap(module.closeSession(session)); releaseErr != nil {
			if err == nil {
				err = releaseErr
			}
		}
	}()

	// find all certificate objects

	certObjs, err := findObjects(module.pkcs11Ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	// find all public key objects

	pubKeyObjs, err := findObjects(module.pkcs11Ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	// find all private key objects

	privKeyObjs, err := findObjects(module.pkcs11Ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, module.certType),
	})
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	// find valid private key + public key + certificate with same ID
	validInfos = module.getValidInfo(&privKeyObjs, &pubKeyObjs, &certObjs)

	// Fill remaining objects as invalid
	invalidKeys = append(invalidKeys, module.getInvaidPkcsURLs(privKeyObjs, "Invalid private key")...)
	invalidKeys = append(invalidKeys, module.getInvaidPkcsURLs(pubKeyObjs, "Invalid public key")...)
	invalidCerts = append(invalidCerts, module.getInvaidPkcsURLs(certObjs, "Invalid certificate")...)

	invlidChains, err := module.getInvalidCertChainURLs(session)
	if err != nil {
		return nil, nil, nil, aoserrors.Wrap(err)
	}

	return validInfos, append(invalidCerts, invlidChains...), invalidKeys, nil
}

// CreateKey creates key pair.
func (module *PKCS11Module) CreateKey(password, algorithm string) (key crypto.PrivateKey, err error) {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Create key")

	if module.crypto11Ctx == nil {
		return nil, aoserrors.Wrap(errNoContext)
	}

	privateKey := pendingKey{id: uuid.New().String()}

	switch strings.ToLower(algorithm) {
	case cryptutils.AlgRSA:
		if privateKey.Signer, err = module.crypto11Ctx.GenerateRSAKeyPairWithLabel(
			[]byte(privateKey.id), []byte(module.certType), rsaKeyLength); err != nil {
			return nil, aoserrors.Wrap(err)
		}

	case cryptutils.AlgECC:
		if privateKey.Signer, err = module.crypto11Ctx.GenerateECDSAKeyPairWithLabel(
			[]byte(privateKey.id), []byte(module.certType), ecsdaCurveID); err != nil {
			return nil, aoserrors.Wrap(err)
		}

	default:
		return nil, aoserrors.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err = module.tokenMemInfo(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	module.pendingKeys.PushBack(privateKey)

	if module.pendingKeys.Len() > maxPendingKeys {
		log.WithFields(log.Fields{"certType": module.certType}).Warn("Max pending keys reached. Remove old.")

		value := module.pendingKeys.Remove(module.pendingKeys.Front())

		if oldKey, ok := value.(pendingKey); ok {
			if err = oldKey.Delete(); err != nil {
				log.Errorf("Can't delete pending key: %s", err)
			}
		} else {
			log.Error("Wrong key type in pending keys list")
		}
	}

	return privateKey, nil
}

// ApplyCertificate applies certificate.
func (module *PKCS11Module) ApplyCertificate(x509Certs []*x509.Certificate) (
	certInfo certhandler.CertInfo, password string, err error,
) {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType}).Debug("Apply certificate")

	if module.crypto11Ctx == nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(errNoContext)
	}

	var (
		currentKey pendingKey
		next       *list.Element
	)

	for e := module.pendingKeys.Front(); e != nil; e = next {
		next = e.Next()

		key, ok := e.Value.(pendingKey)
		if !ok {
			log.Error("Wrong key type in pending keys list")
			continue
		}

		if cryptutils.CheckCertificate(x509Certs[0], key) == nil {
			currentKey = key

			module.pendingKeys.Remove(e)

			break
		}
	}

	if currentKey.Signer == nil {
		return certhandler.CertInfo{}, "", aoserrors.New("no corresponding key found")
	}

	if err = module.createCertificateChain(currentKey.id, module.certType, x509Certs); err != nil {
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	certInfo.CertURL = module.createURL(module.certType, currentKey.id)
	certInfo.KeyURL = module.createURL(module.certType, currentKey.id)
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
		return certhandler.CertInfo{}, "", aoserrors.Wrap(err)
	}

	return certInfo, "", nil
}

// RemoveCertificate removes certificate.
func (module *PKCS11Module) RemoveCertificate(certURL, password string) error {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType, "certURL": certURL}).Debug("Remove certificate")

	if module.crypto11Ctx == nil {
		return aoserrors.Wrap(errNoContext)
	}

	urlTemplate, err := parseURL(certURL)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	template := crypto11.NewAttributeSet()

	template.AddIfNotPresent(urlTemplate)

	if err := module.crypto11Ctx.DeleteCertificateWithAttributes(template); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// RemoveKey removes key.
func (module *PKCS11Module) RemoveKey(keyURL, password string) error {
	module.Lock()
	defer module.Unlock()

	log.WithFields(log.Fields{"certType": module.certType, "keyURL": keyURL}).Debug("Remove key")

	if module.crypto11Ctx == nil {
		return aoserrors.Wrap(errNoContext)
	}

	urlTemplate, err := parseURL(keyURL)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	template := crypto11.NewAttributeSet()

	template.AddIfNotPresent(urlTemplate)

	keyPair, err := module.crypto11Ctx.FindKeyPairWithAttributes(template)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if keyPair != nil {
		if err := keyPair.Delete(); err != nil {
			return aoserrors.Wrap(err)
		}
	}

	return nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (module *PKCS11Module) createCurrentContext() (err error) {
	log.WithFields(log.Fields{"slotID": module.slotID}).Debug("Create current context")

	if module.userPIN, err = module.getUserPIN(); err != nil {
		return aoserrors.Wrap(err)
	}

	slotID := int(module.slotID)

	if module.crypto11Ctx, err = crypto11.Configure(&crypto11.Config{
		Path:       module.config.Library,
		SlotNumber: &slotID,
		Pin:        module.userPIN,
	}); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (module *PKCS11Module) closeCurrentContext() error {
	if module.crypto11Ctx != nil {
		log.WithFields(log.Fields{"slotID": module.slotID}).Debug("Close current context")

		if err := module.crypto11Ctx.Close(); err != nil {
			return aoserrors.Wrap(err)
		}
	}

	module.crypto11Ctx = nil

	log.WithFields(log.Fields{"slotID": module.slotID}).Debug("Close all sessions")

	if err := module.pkcs11Ctx.CloseAllSessions(module.slotID); err != nil {
		return aoserrors.Wrap(err)
	}

	module.pendingKeys = list.New()

	return nil
}

func (module *PKCS11Module) getInvalidCertChainURLs(session pkcs11.SessionHandle) (invalidCerts []string, err error) {
	// Check certificate chains
	invalidChainCerts, err := checkCertificateChain(module.pkcs11Ctx, session)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, cert := range invalidChainCerts {
		log.WithFields(log.Fields{"id": cert.id}).Warn("Invalid chain certificate")

		invalidCerts = append(invalidCerts, module.createURL("", cert.id))
	}

	return invalidCerts, nil
}

func (module *PKCS11Module) isOwned() (bool, error) {
	tokenInfo, err := module.pkcs11Ctx.GetTokenInfo(module.slotID)
	if err != nil {
		return false, aoserrors.Wrap(err)
	}

	return tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0, nil
}

func findObjectIndexByID(id string, objs []*pkcs11Object) (index int, err error) {
	for i, obj := range objs {
		if obj.id == id {
			return i, nil
		}
	}

	return 0, aoserrors.New("object not found")
}

func getTeeUserPIN(loginType string, uid, gid uint32) (string, error) {
	switch loginType {
	case loginTypePublic:
		return loginType, nil

	case loginTypeUser:
		return fmt.Sprintf("%s:%s", loginType, uuid.NewSHA1(teeClientUUIDNs, []byte(fmt.Sprintf("uid=%d", uid)))), nil

	case loginTypeGroup:
		return fmt.Sprintf("%s:%s", loginType, uuid.NewSHA1(teeClientUUIDNs, []byte(fmt.Sprintf("gid=%d", gid)))), nil

	default:
		return "", aoserrors.Errorf("wrong TEE login type: %s", loginType)
	}
}

func parseURL(urlStr string) (template []*pkcs11.Attribute, err error) {
	urlVal, err := url.Parse(urlStr)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	_, _, label, id, _ := cryptutils.ParsePKCS11Url(urlVal) //nolint:dogsled

	if id != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}

	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	return template, nil
}

func (module *PKCS11Module) createURL(label, id string) string {
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

func (module *PKCS11Module) createSession(userLogin bool, pin string) (pkcs11.SessionHandle, error) {
	session, err := module.pkcs11Ctx.OpenSession(module.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("Create session")

	info, err := module.pkcs11Ctx.GetSessionInfo(session)
	if err != nil {
		return 0, aoserrors.Wrap(err)
	}

	isUserLoggedIn := info.State == CKS_RO_USER_FUNCTIONS || info.State == CKS_RW_USER_FUNCTIONS
	isSOLoggedIn := info.State == CKS_RW_SO_FUNCTIONS

	if (userLogin && isSOLoggedIn) || (!userLogin && isUserLoggedIn) {
		if err = module.pkcs11Ctx.Logout(session); err != nil {
			return 0, aoserrors.Wrap(err)
		}
	}

	if userLogin && !isUserLoggedIn {
		log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("User login")

		if err = module.pkcs11Ctx.Login(session, pkcs11.CKU_USER, module.userPIN); err != nil {
			return 0, aoserrors.Wrap(err)
		}
	}

	if !userLogin && !isSOLoggedIn {
		log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("SO login")

		if err = module.pkcs11Ctx.Login(session, pkcs11.CKU_SO, pin); err != nil {
			return 0, aoserrors.Wrap(err)
		}
	}

	return session, nil
}

func (module *PKCS11Module) closeSession(session pkcs11.SessionHandle) error {
	log.WithFields(log.Fields{"session": session, "slotID": module.slotID}).Debug("Close session")

	if err := module.pkcs11Ctx.CloseSession(session); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (module *PKCS11Module) getUserPIN() (pin string, err error) {
	if module.teeLoginType != "" {
		return "", nil
	}

	data, err := os.ReadFile(module.config.UserPINPath)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	return string(data), nil
}

func (module *PKCS11Module) getTokenLabel() (label string) {
	if module.config.TokenLabel != "" {
		return module.config.TokenLabel
	}

	return defaultTokenLabel
}

// Find our slot either by slotId or by slot index or by tokenLabel
// If neither one is specified try to find slot by default token label.
// If slot is not found, try to find first free slot.

func (module *PKCS11Module) getSlotID() (uint, error) {
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

	if paramCount >= 2 { //nolint:gomnd
		return 0, aoserrors.New(
			"only one parameter for slot identification should be specified (slotId or slotIndex or tokenLabel)")
	}

	if module.config.SlotID != nil {
		return *module.config.SlotID, nil
	}

	slotIDs, err := module.pkcs11Ctx.GetSlotList(false)
	if err != nil {
		return 0, aoserrors.Wrap(err)
	}

	if module.config.SlotIndex != nil {
		if *module.config.SlotIndex >= len(slotIDs) || *module.config.SlotIndex < 0 {
			return 0, aoserrors.New("invalid slot index")
		}

		return slotIDs[*module.config.SlotIndex], nil
	}

	var (
		freeID    uint
		freeFound bool
	)

	for _, id := range slotIDs {
		slotInfo, err := module.pkcs11Ctx.GetSlotInfo(id)
		if err != nil {
			return 0, aoserrors.Wrap(err)
		}

		if slotInfo.Flags&pkcs11.CKF_TOKEN_PRESENT != 0 {
			tokenInfo, err := module.pkcs11Ctx.GetTokenInfo(id)
			if err != nil {
				return 0, aoserrors.Wrap(err)
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

	return 0, aoserrors.New("no suitable slot found")
}

func (module *PKCS11Module) displayInfo(slotID uint) error {
	libInfo, err := module.pkcs11Ctx.GetInfo()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"library":         module.config.Library,
		"cryptokiVersion": fmt.Sprintf("%d.%d", libInfo.CryptokiVersion.Major, libInfo.CryptokiVersion.Minor),
		"manufacturer":    libInfo.ManufacturerID,
		"description":     libInfo.LibraryDescription,
		"libraryVersion":  fmt.Sprintf("%d.%d", libInfo.LibraryVersion.Major, libInfo.LibraryVersion.Minor),
	}).Debug("Library info")

	slotInfo, err := module.pkcs11Ctx.GetSlotInfo(slotID)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"slotID":       slotID,
		"manufacturer": slotInfo.ManufacturerID,
		"description":  slotInfo.SlotDescription,
		"hwVersion":    fmt.Sprintf("%d.%d", slotInfo.HardwareVersion.Major, slotInfo.HardwareVersion.Major),
		"fwVersion":    fmt.Sprintf("%d.%d", slotInfo.FirmwareVersion.Major, slotInfo.FirmwareVersion.Major),
		"flags":        slotInfo.Flags,
	}).Debug("Slot info")

	tokenInfo, err := module.pkcs11Ctx.GetTokenInfo(slotID)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"slotID":       slotID,
		"label":        tokenInfo.Label,
		"manufacturer": tokenInfo.ManufacturerID,
		"model":        tokenInfo.Model,
		"serial":       tokenInfo.SerialNumber,
		"hwVersion":    fmt.Sprintf("%d.%d", tokenInfo.HardwareVersion.Major, tokenInfo.HardwareVersion.Major),
		"fwVersion":    fmt.Sprintf("%d.%d", tokenInfo.FirmwareVersion.Major, tokenInfo.FirmwareVersion.Major),
		"publicMemory": fmt.Sprintf("%d/%d", tokenInfo.TotalPublicMemory-tokenInfo.FreePublicMemory,
			tokenInfo.TotalPublicMemory),
		"privateMemory": fmt.Sprintf("%d/%d", tokenInfo.TotalPrivateMemory-tokenInfo.FreePrivateMemory,
			tokenInfo.TotalPrivateMemory),
		"flags": tokenInfo.Flags,
	}).Debug("Token info")

	return nil
}

func (module *PKCS11Module) tokenMemInfo() error {
	tokenInfo, err := module.pkcs11Ctx.GetTokenInfo(module.slotID)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"publicMemory": fmt.Sprintf(
			"%d/%d", tokenInfo.TotalPublicMemory-tokenInfo.FreePublicMemory, tokenInfo.TotalPublicMemory),
		"privateMemory": fmt.Sprintf(
			"%d/%d", tokenInfo.TotalPrivateMemory-tokenInfo.FreePrivateMemory, tokenInfo.TotalPrivateMemory),
	}).Debug("Token mem info")

	return nil
}

func (module *PKCS11Module) getInvaidPkcsURLs(objects []*pkcs11Object, warnMsg string) (invalidObjURLs []string) {
	for _, obj := range objects {
		log.WithFields(log.Fields{"id": obj.id}).Warn(warnMsg)

		invalidObjURLs = append(invalidObjURLs, module.createURL(module.certType, obj.id))
	}

	return invalidObjURLs
}

func (module *PKCS11Module) getValidInfo(privKeyObjs, pubKeyObjs,
	certObjs *[]*pkcs11Object,
) (validInfos []certhandler.CertInfo) {
	k := 0

	for i, privKeyObj := range *privKeyObjs {
		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Private key found")

		pubKeyIndex, err := findObjectIndexByID(privKeyObj.id, *pubKeyObjs)
		if err != nil {
			continue
		}

		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Public key found")

		certIndex, err := findObjectIndexByID(privKeyObj.id, *certObjs)
		if err != nil {
			continue
		}

		log.WithFields(log.Fields{"id": privKeyObj.id}).Debug("Certificate found")

		cert := &pkcs11Certificate{pkcs11Object: *(*certObjs)[certIndex]}

		x509Cert, err := cert.getX509Certificate()
		if err != nil {
			log.WithFields(log.Fields{"id": cert.id}).Errorf("Can't get x509 certificate: %s", err)

			continue
		}

		validInfos = append(validInfos, certhandler.CertInfo{
			Issuer:   base64.StdEncoding.EncodeToString(x509Cert.RawIssuer),
			Serial:   fmt.Sprintf("%X", x509Cert.SerialNumber),
			NotAfter: x509Cert.NotAfter,
			CertURL:  module.createURL(module.certType, (*certObjs)[certIndex].id),
			KeyURL:   module.createURL(module.certType, privKeyObj.id),
		})

		(*privKeyObjs)[i], (*privKeyObjs)[k] = (*privKeyObjs)[k], privKeyObj
		k++

		*certObjs = append((*certObjs)[:certIndex], (*certObjs)[certIndex+1:]...)
		*pubKeyObjs = append((*pubKeyObjs)[:pubKeyIndex], (*pubKeyObjs)[pubKeyIndex+1:]...)
	}

	*privKeyObjs = (*privKeyObjs)[k:]

	return validInfos
}

func (module *PKCS11Module) createCertificateChain(id, label string, x509Certs []*x509.Certificate) error {
	if err := module.crypto11Ctx.ImportCertificateWithLabel([]byte(id), []byte(label), x509Certs[0]); err != nil {
		return aoserrors.Wrap(err)
	}

	for _, cert := range x509Certs[1:] {
		template := crypto11.NewAttributeSet()

		if err := template.Set(pkcs11.CKA_ISSUER, cert.RawIssuer); err != nil {
			return aoserrors.Wrap(err)
		}

		serial, err := asn1.Marshal(cert.SerialNumber)
		if err != nil {
			return aoserrors.Wrap(err)
		}

		if err := template.Set(pkcs11.CKA_SERIAL_NUMBER, serial); err != nil {
			return aoserrors.Wrap(err)
		}

		existCert, err := module.crypto11Ctx.FindCertificateWithAttributes(template)
		if err != nil {
			return aoserrors.Wrap(err)
		}

		if existCert != nil {
			continue
		}

		if err := module.crypto11Ctx.ImportCertificate([]byte(uuid.New().String()), cert); err != nil {
			return aoserrors.Wrap(err)
		}
	}

	return nil
}
