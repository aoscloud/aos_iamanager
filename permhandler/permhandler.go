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

	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/aoserrors"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	secretLength         = 8
	attemptsCreateSecret = 10
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type secretKey string

// Handler update handler
type Handler struct {
	sync.Mutex

	secrets map[secretKey]servicePermissions
}

type servicePermissions struct {
	serviceID   string
	permissions map[string]map[string]string
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New returns pointer to new Handler
func New() (handler *Handler, err error) {
	handler = &Handler{}

	handler.secrets = make(map[secretKey]servicePermissions)

	log.Debug("Create permission handler")

	return handler, nil
}

// RegisterService adds new service into cache and creates secret
func (handler *Handler) RegisterService(serviceID string, funcServerPermissions map[string]map[string]string) (secret string, err error) {
	handler.Lock()
	defer handler.Unlock()

	log.WithField("serviceID", serviceID).Debug("Register service")

	if secret, err := handler.findServiceID(serviceID); err == nil {
		log.Warnf("Service %s is already registered", serviceID)
		return secret, nil
	}

	newSecret, err := handler.tryGenerateSecret()
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	handler.secrets[newSecret] = servicePermissions{serviceID: serviceID, permissions: funcServerPermissions}

	return string(newSecret), nil
}

// UnregisterService deletes service with permissions from cache
func (handler *Handler) UnregisterService(serviceID string) {
	handler.Lock()
	defer handler.Unlock()

	log.WithField("serviceID", serviceID).Debug("Unregister service")

	secret, err := handler.findServiceID(serviceID)
	if err != nil {
		log.Warnf("Service %s is not registered", serviceID)
		return
	}

	delete(handler.secrets, secretKey(secret))
}

// GetPermissions returns service id and permissions by secret and functional server ID
func (handler *Handler) GetPermissions(secret, funcServerId string) (serviceID string, permissions map[string]string, err error) {
	handler.Lock()
	defer handler.Unlock()

	log.WithField("funcServerId", funcServerId).Debug("Get permissions")

	funcServersPermissions, ok := handler.secrets[secretKey(secret)]
	if !ok {
		return "", nil, aoserrors.New("secret not found")
	}

	permissions, ok = funcServersPermissions.permissions[funcServerId]
	if !ok {
		return "", nil, aoserrors.Errorf("permissions for functional server %s not found", funcServerId)
	}

	return funcServersPermissions.serviceID, permissions, nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

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

func (handler *Handler) findServiceID(serviceID string) (secret string, err error) {
	for key, value := range handler.secrets {
		if value.serviceID == serviceID {
			return string(key), nil
		}
	}

	return "", aoserrors.Errorf("service ID %s not found", serviceID)
}
