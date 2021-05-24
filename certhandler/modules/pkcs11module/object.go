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
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

/*******************************************************************************
 * Const
 ******************************************************************************/

const maxFindObjects = 32

/*******************************************************************************
 * Types
 ******************************************************************************/

type pkcs11Object struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	handle  pkcs11.ObjectHandle
	id      string
	label   string
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (object *pkcs11Object) getID() (id string) {
	return object.id
}

func (object *pkcs11Object) delete() (err error) {
	log.WithFields(log.Fields{
		"session": object.session,
		"handle":  object.handle,
		"id":      object.id}).Debug("Delete object")

	if err = object.ctx.DestroyObject(object.session, object.handle); err != nil {
		return err
	}

	return nil
}

func findObjects(ctx *pkcs11.Ctx, session pkcs11.SessionHandle,
	template []*pkcs11.Attribute) (objects []*pkcs11Object, err error) {
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true))

	if err = ctx.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	defer func() {
		if err := ctx.FindObjectsFinal(session); err != nil {
			log.Errorf("Can't finalize find objects: %s", err)
		}
	}()

	for {
		handles, _, err := ctx.FindObjects(session, maxFindObjects)
		if err != nil {
			return nil, err
		}

		if len(handles) == 0 {
			break
		}

		for _, handle := range handles {
			attributes, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil), pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil)})
			if err != nil {
				return nil, err
			}

			objects = append(objects, &pkcs11Object{
				ctx:     ctx,
				session: session,
				handle:  handle,
				id:      string(attributes[0].Value),
				label:   string(attributes[1].Value),
			})
		}
	}

	return objects, nil
}
