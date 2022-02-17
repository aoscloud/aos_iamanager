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
	"errors"

	"github.com/ThalesIgnite/crypto11"
	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type pkcs11Certificate struct {
	pkcs11Object
	subject []byte
	issuer  []byte
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errCertNotFound = errors.New("certificate not found")

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (cert *pkcs11Certificate) getX509Certificate() (*x509.Certificate, error) {
	attributes, err := cert.ctx.GetAttributeValue(cert.session, cert.handle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	x509Cert, err := x509.ParseCertificate(attributes[0].Value)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return x509Cert, nil
}

func findCertificates(ctx *crypto11.PKCS11Context, session pkcs11.SessionHandle,
	template []*pkcs11.Attribute) (certs []*pkcs11Certificate, err error) {
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

	objects, err := findObjects(ctx, session, template)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, object := range objects {
		attributes, err := ctx.GetAttributeValue(session, object.handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil), pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil),
		})
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		certs = append(certs, &pkcs11Certificate{
			pkcs11Object: *object,
			subject:      attributes[0].Value,
			issuer:       attributes[1].Value,
		})
	}

	return certs, nil
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

func checkCertificateChain(
	ctx *crypto11.PKCS11Context, session pkcs11.SessionHandle) ([]*pkcs11Certificate, error) {
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
