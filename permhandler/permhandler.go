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

package permhandler

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	secretLength         = 8
	attemptsCreateSecret = 10
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type secretKey string

// Handler update handler.
type Handler struct {
	sync.Mutex

	secrets map[secretKey]instancePermissions
}

type instancePermissions struct {
	instaneIdent aostypes.InstanceIdent
	permissions  map[string]map[string]string
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New returns pointer to new Handler.
func New() (handler *Handler, err error) {
	handler = &Handler{}

	handler.secrets = make(map[secretKey]instancePermissions)

	log.Debug("Create permission handler")

	return handler, nil
}

// RegisterInstance adds new service instance into cache and creates secret.
func (handler *Handler) RegisterInstance(
	instance aostypes.InstanceIdent, permissions map[string]map[string]string,
) (secret string, err error) {
	handler.Lock()
	defer handler.Unlock()

	if secret, err := handler.getSecretForInstance(instance); err == nil {
		return secret, nil
	}

	newSecret, err := handler.tryGenerateSecret()
	if err != nil {
		return "", err
	}

	handler.secrets[newSecret] = instancePermissions{instaneIdent: instance, permissions: permissions}

	return string(newSecret), nil
}

// UnregisterInstance deletes service instance with permissions from cache.
func (handler *Handler) UnregisterInstance(instance aostypes.InstanceIdent) {
	handler.Lock()
	defer handler.Unlock()

	secret, err := handler.getSecretForInstance(instance)
	if err != nil {
		log.WithFields(log.Fields{
			"serviceID": instance.ServiceID,
			"subjectID": instance.SubjectID,
			"instance":  instance.Instance,
		}).Warn("Instance not registered")

		return
	}

	delete(handler.secrets, secretKey(secret))
}

// GetPermissions returns instance and permissions by secret and functional server ID.
func (handler *Handler) GetPermissions(
	secret, funcServerID string,
) (instance aostypes.InstanceIdent, permissions map[string]string, err error) {
	handler.Lock()
	defer handler.Unlock()

	funcServersPermissions, ok := handler.secrets[secretKey(secret)]
	if !ok {
		return instance, nil, aoserrors.New("secret not found")
	}

	permissions, ok = funcServersPermissions.permissions[funcServerID]
	if !ok {
		return instance, nil, aoserrors.Errorf("permissions for functional server %s not found", funcServerID)
	}

	return funcServersPermissions.instaneIdent, permissions, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (handler *Handler) tryGenerateSecret() (secret secretKey, err error) {
	for i := 0; i < attemptsCreateSecret; i++ {
		secret, err := generateSecret()
		if err != nil {
			return "", aoserrors.Wrap(err)
		}

		if _, ok := handler.secrets[secret]; !ok {
			return secret, nil
		}
	}

	return "", aoserrors.New("max secrete generation attempts reached")
}

func generateSecret() (secret secretKey, err error) {
	b := make([]byte, secretLength)

	if _, err = rand.Read(b); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return secretKey(base64.StdEncoding.EncodeToString(b)), nil
}

func (handler *Handler) getSecretForInstance(instance aostypes.InstanceIdent) (string, error) {
	for key, value := range handler.secrets {
		if value.instaneIdent == instance {
			return string(key), nil
		}
	}

	return "", aoserrors.New("instace not found")
}
