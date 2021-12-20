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
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type pkcs11Certificate struct {
	pkcs11Object
	subject []byte
	issuer  []byte
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var errCertNotFound = errors.New("certificate not found")

/*******************************************************************************
 * Private
 ******************************************************************************/

func (cert *pkcs11Certificate) getX509Certificate() (x509Cert *x509.Certificate, err error) {
	attributes, err := cert.ctx.GetAttributeValue(cert.session, cert.handle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if x509Cert, err = x509.ParseCertificate(attributes[0].Value); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return x509Cert, nil
}

func createCertificateChain(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, x509Certs []*x509.Certificate) (cert *pkcs11Certificate, err error) {
	log.WithFields(log.Fields{
		"session": session,
		"id":      id,
		"label":   label}).Debug("Create certificate chain")

	if len(x509Certs) == 0 {
		return nil, aoserrors.New("empty certificate chain")
	}

	if err = updateIssuerCertificates(ctx, session, x509Certs[1:]); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if cert, err = createCertificate(ctx, session, id, label, x509Certs[0]); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return cert, nil
}

func createCertificate(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, x509Cert *x509.Certificate) (cert *pkcs11Certificate, err error) {

	serial, err := asn1.Marshal(x509Cert.SerialNumber)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, x509Cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, x509Cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, x509Cert.Raw),
	}

	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	handle, err := ctx.CreateObject(session, template)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{
		"session": session,
		"id":      id,
		"label":   label,
		"subject": x509Cert.Subject,
		"issuer":  x509Cert.Issuer,
		"handle":  handle,
	}).Debug("Create certificate")

	return &pkcs11Certificate{pkcs11Object: pkcs11Object{ctx: ctx, session: session, handle: handle}}, nil
}

func updateIssuerCertificates(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	x509Certs []*x509.Certificate) (err error) {
	for _, x509Cert := range x509Certs {
		if len(x509Cert.RawSubject) == 0 {
			return aoserrors.New("subject is nil")
		}

		if _, err = findCertificateBySubject(ctx, session, x509Cert.RawSubject); err != nil {
			if err != errCertNotFound {
				return aoserrors.Wrap(err)
			}

			log.WithFields(log.Fields{
				"session": session,
				"subject": x509Cert.Subject,
			}).Debug("Certificate not found")

			if _, err = createCertificate(ctx, session, uuid.New().String(), "", x509Cert); err != nil {
				return aoserrors.Wrap(err)
			}
		}
	}

	return nil
}

func findCertificates(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	template []*pkcs11.Attribute) (certs []*pkcs11Certificate, err error) {
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

	objects, err := findObjects(ctx, session, template)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, object := range objects {
		attributes, err := ctx.GetAttributeValue(session, object.handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil), pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil)})
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		certs = append(certs, &pkcs11Certificate{
			pkcs11Object: *object,
			subject:      attributes[0].Value,
			issuer:       attributes[1].Value})
	}

	return certs, nil
}

func findCertificateBySubject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	subject []byte) (cert *pkcs11Certificate, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, subject),
	}

	certs, err := findCertificates(ctx, session, template)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if len(certs) == 0 {
		return nil, errCertNotFound
	}

	return certs[0], nil
}

func findCertificateChain(cert *pkcs11Certificate,
	chainCerts []*pkcs11Certificate) (certs []*pkcs11Certificate, err error) {
	if len(cert.issuer) == 0 || bytes.Equal(cert.issuer, cert.subject) {
		return nil, nil
	}

	var (
		found bool
		index int
	)

	for i, chainCert := range chainCerts {
		if bytes.Equal(cert.issuer, chainCert.subject) {
			found = true
			index = i

			break
		}
	}

	if !found {
		log.WithFields(log.Fields{"id": cert.id}).Debug("Chain certificate not found by issuer")

		x509Cert, err := cert.getX509Certificate()
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		for i, chainCert := range chainCerts {
			x509ChainCert, err := chainCert.getX509Certificate()
			if err != nil {
				return nil, aoserrors.Wrap(err)
			}

			if bytes.Equal(x509Cert.AuthorityKeyId, x509ChainCert.SubjectKeyId) {
				found = true
				index = i

				break
			}
		}
	}

	if !found {
		return nil, aoserrors.Wrap(errCertNotFound)
	}

	cert = chainCerts[index]

	for _, foundCert := range certs {
		if bytes.Equal(cert.subject, foundCert.subject) {
			return certs, nil
		}
	}

	certs = append(certs, cert)

	restCerts, err := findCertificateChain(cert, chainCerts)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if len(restCerts) > 0 {
		certs = append(certs, restCerts...)
	}

	return certs, nil
}

func appendIfNotExist(certs []*pkcs11Certificate, cert *pkcs11Certificate) (newCerts []*pkcs11Certificate) {
	for _, existCert := range certs {
		if existCert.handle == cert.handle {
			return certs
		}
	}

	return append(certs, cert)
}

func checkCertificateChain(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) (invalidCerts []*pkcs11Certificate, err error) {
	log.Debug("Checking certificate chain")

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	certs, err := findCertificates(ctx, session, template)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	var chainCerts, mainCerts []*pkcs11Certificate

	for _, cert := range certs {
		if cert.label == "" {
			chainCerts = append(chainCerts, cert)
		} else {
			mainCerts = append(mainCerts, cert)
		}
	}

	var foundChainCerts []*pkcs11Certificate

	for _, cert := range mainCerts {
		foundCerts, err := findCertificateChain(cert, chainCerts)
		if err != nil {
			log.Errorf("Find certificate chain error: %s", err)
		}

		for _, foundCert := range foundCerts {
			foundChainCerts = appendIfNotExist(foundChainCerts, foundCert)
		}
	}

	for _, foundCert := range foundChainCerts {
		i := 0

		for _, chainCert := range chainCerts {
			if foundCert.handle != chainCert.handle {
				chainCerts[i] = chainCert
				i++
			}
		}

		chainCerts = chainCerts[:i]
	}

	return chainCerts, nil
}
