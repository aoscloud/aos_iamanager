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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"unsafe"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/aoserrors"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type pkcs11PrivateKey struct {
	pkcs11Object
	publicKey       crypto.PublicKey
	publicKeyHandle pkcs11.ObjectHandle
}

type pkcs11PrivateKeyRSA struct {
	pkcs11PrivateKey
}

type pkcs11PrivateKeyECC struct {
	pkcs11PrivateKey
}

type ecdsaSignature struct {
	R, S *big.Int
}

type privateKey interface {
	getID() (id string)
	moveToToken() (err error)
	delete() (err error)
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

var curvesMap = map[elliptic.Curve][]byte{
	elliptic.P224(): mustMarshalASN1(asn1.ObjectIdentifier{1, 3, 132, 0, 33}),
	elliptic.P256(): mustMarshalASN1(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
	elliptic.P384(): mustMarshalASN1(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
	elliptic.P521(): mustMarshalASN1(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

func (key *pkcs11PrivateKey) Public() (publicKey crypto.PublicKey) {
	return key.publicKey
}

func (key *pkcs11PrivateKeyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var mechanisms []*pkcs11.Mechanism

	switch opts := opts.(type) {
	case *rsa.PSSOptions:
		hashAlg, mgfAlg, hashLen, err := hashToPKCS11(opts.Hash)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		saltLen := uint32(opts.SaltLength)

		switch opts.SaltLength {
		case rsa.PSSSaltLengthAuto:
			return nil, aoserrors.Errorf("unsupported salt length: %v", opts.SaltLength)

		case rsa.PSSSaltLengthEqualsHash:
			saltLen = hashLen
		}

		parameters := []byte{}

		parameters = append(parameters, uin32ToBytes(hashAlg)...)
		parameters = append(parameters, uin32ToBytes(mgfAlg)...)
		parameters = append(parameters, uin32ToBytes(saltLen)...)

		mechanisms = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)}

	default:
		oid, ok := pkcs1Prefix[opts.HashFunc()]
		if !ok {
			return nil, aoserrors.Errorf("unsupported hash function: %v", opts.HashFunc())
		}

		digest = append(oid, digest...)
		mechanisms = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	}

	if err = key.ctx.SignInit(key.session, mechanisms, key.handle); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if signature, err = key.ctx.Sign(key.session, digest); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return signature, nil
}

func (key *pkcs11PrivateKeyECC) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	mechanisms := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

	if err = key.ctx.SignInit(key.session, mechanisms, key.handle); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if signature, err = key.ctx.Sign(key.session, digest); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	ecdsaSignature, err := unmarshalECDSASignature(signature)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if signature, err = asn1.Marshal(ecdsaSignature); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return signature, nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func uin32ToBytes(value uint32) (result []byte) {
	result = make([]byte, unsafe.Sizeof(value))

	binary.LittleEndian.PutUint32(result, value)

	return result
}

func hashToPKCS11(hashFunction crypto.Hash) (hashAlg uint32, mgfAlg uint32, hashLen uint32, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, uint32(pkcs11.CKG_MGF1_SHA1), 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, uint32(pkcs11.CKG_MGF1_SHA224), 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, uint32(pkcs11.CKG_MGF1_SHA256), 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, uint32(pkcs11.CKG_MGF1_SHA384), 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, uint32(pkcs11.CKG_MGF1_SHA512), 64, nil
	default:
		return 0, 0, 0, aoserrors.Errorf("unsupported hash function: %v", hashFunction)
	}
}

func mustMarshalASN1(val interface{}) (oid []byte) {
	var err error

	if oid, err = asn1.Marshal(val); err != nil {
		panic(err)
	}

	return oid
}

func marshalCurve(curve elliptic.Curve) (oid []byte, err error) {
	var ok bool

	if oid, ok = curvesMap[curve]; !ok {
		return nil, aoserrors.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	return oid, aoserrors.Wrap(err)
}

func unmarshalCurve(oid []byte) (curve elliptic.Curve, err error) {
	for curve, curveOid := range curvesMap {
		if bytes.Equal(curveOid, oid) {
			return curve, nil
		}
	}

	return nil, aoserrors.New("unsupported curve")
}

func unmarshalECPoint(point []byte, curve elliptic.Curve) (x *big.Int, y *big.Int, err error) {
	var pointBytes []byte

	if _, err = asn1.Unmarshal(point, &pointBytes); err != nil {
		return nil, nil, aoserrors.New("can't unmarshal EC point")
	}

	if x, y = elliptic.Unmarshal(curve, pointBytes); x == nil || y == nil {
		return nil, nil, aoserrors.New("can't unmarshal EC point")
	}

	return x, y, nil
}

func unmarshalECDSASignature(data []byte) (signature ecdsaSignature, err error) {
	if len(data) == 0 || len(data)%2 != 0 {
		return ecdsaSignature{}, aoserrors.New("ECDSA signature length is invalid from")
	}

	n := len(data) / 2

	signature.R, signature.S = new(big.Int), new(big.Int)

	signature.R.SetBytes(data[:n])
	signature.S.SetBytes(data[n:])

	return signature, nil
}

func (key *pkcs11PrivateKey) delete() (err error) {
	publicObject := pkcs11Object{
		ctx:     key.ctx,
		session: key.session,
		handle:  key.publicKeyHandle,
		id:      key.id,
	}

	if err = publicObject.delete(); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = key.pkcs11Object.delete(); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (key *pkcs11PrivateKey) moveToToken() (err error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true)}

	newPublicHandle, err := key.ctx.CopyObject(key.session, key.publicKeyHandle, template)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"session":   key.session,
		"handle":    key.publicKeyHandle,
		"newHandle": newPublicHandle}).Debug("Copy public key to token")

	newPrivateHandle, err := key.ctx.CopyObject(key.session, key.handle, template)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"session":   key.session,
		"handle":    key.handle,
		"newHandle": newPrivateHandle}).Debug("Copy private key to token")

	if err = key.delete(); err != nil {
		return aoserrors.Wrap(err)
	}

	key.publicKeyHandle, key.handle = newPublicHandle, newPrivateHandle

	return nil
}

func (key *pkcs11PrivateKeyRSA) loadPublicKey() (err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	attributes, err := key.ctx.GetAttributeValue(key.session, key.publicKeyHandle, template)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	var modulus = new(big.Int).SetBytes(attributes[0].Value)
	var exponent = new(big.Int).SetBytes(attributes[1].Value)

	if exponent.BitLen() > 32 || exponent.Sign() < 1 || int(exponent.Uint64()) < 2 {
		return aoserrors.New("invalid RSA public key")
	}

	key.publicKey = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}

	return nil
}

func (key *pkcs11PrivateKeyECC) loadPublicKey() (err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attributes, err := key.ctx.GetAttributeValue(key.session, key.publicKeyHandle, template)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	var publicKey ecdsa.PublicKey

	if publicKey.Curve, err = unmarshalCurve(attributes[0].Value); err != nil {
		return aoserrors.Wrap(err)
	}

	if publicKey.X, publicKey.Y, err = unmarshalECPoint(attributes[1].Value, publicKey.Curve); err != nil {
		return aoserrors.Wrap(err)
	}

	key.publicKey = &publicKey

	return nil
}

func createRSAKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, keyLength int) (key privateKey, err error) {
	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keyLength),
	}

	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	mechanisms := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}

	publicHandle, privateHandle, err := ctx.GenerateKeyPair(session, mechanisms, publicTemplate, privateTemplate)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"session":       session,
		"id":            id,
		"label":         label,
		"publicHandle":  publicHandle,
		"privateHandle": privateHandle}).Debug("Generate RSA key")

	rsaKey := &pkcs11PrivateKeyRSA{
		pkcs11PrivateKey: pkcs11PrivateKey{
			pkcs11Object: pkcs11Object{
				ctx:     ctx,
				session: session,
				handle:  privateHandle,
				id:      id,
				label:   label,
			},
			publicKeyHandle: publicHandle,
		},
	}

	if err = rsaKey.loadPublicKey(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return rsaKey, nil
}

func createECCKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, curve elliptic.Curve) (key privateKey, err error) {
	parameters, err := marshalCurve(curve)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, parameters),
	}

	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	mechanisms := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}

	publicHandle, privateHandle, err := ctx.GenerateKeyPair(session, mechanisms, publicTemplate, privateTemplate)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"session":       session,
		"id":            id,
		"label":         label,
		"publicHandle":  publicHandle,
		"privateHandle": privateHandle}).Debug("Generate ECC key")

	eccKey := &pkcs11PrivateKeyECC{
		pkcs11PrivateKey: pkcs11PrivateKey{
			pkcs11Object: pkcs11Object{
				ctx:     ctx,
				session: session,
				handle:  privateHandle,
				id:      id,
				label:   label,
			},
			publicKeyHandle: publicHandle,
		},
	}

	if err = eccKey.loadPublicKey(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return eccKey, nil
}
