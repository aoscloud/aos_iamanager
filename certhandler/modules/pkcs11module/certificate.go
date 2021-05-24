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
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"

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

func createCertificateChain(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, x509Certs []*x509.Certificate) (cert *pkcs11Certificate, err error) {
	log.WithFields(log.Fields{
		"session": session,
		"id":      id,
		"label":   label}).Debug("Create certificate chain")

	if len(x509Certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	if err = updateIssuerCertificates(ctx, session, x509Certs[1:]); err != nil {
		return nil, err
	}

	return createCertificate(ctx, session, id, label, x509Certs[0])
}

func createCertificate(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	id, label string, x509Cert *x509.Certificate) (cert *pkcs11Certificate, err error) {

	serial, err := asn1.Marshal(x509Cert.SerialNumber)
	if err != nil {
		return nil, err
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
		return nil, err
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
			return errors.New("subject is nil")
		}

		if _, err = findCertificateBySubject(ctx, session, x509Cert.RawSubject); err != nil {
			if err != errCertNotFound {
				return err
			}

			log.WithFields(log.Fields{
				"session": session,
				"subject": x509Cert.Subject,
			}).Debug("Certificate not found")

			if _, err = createCertificate(ctx, session, uuid.New().String(), "", x509Cert); err != nil {
				return err
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
		return nil, err
	}

	for _, object := range objects {
		attributes, err := ctx.GetAttributeValue(session, object.handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil), pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil)})
		if err != nil {
			return nil, err
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
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errCertNotFound
	}

	return certs[0], nil
}
