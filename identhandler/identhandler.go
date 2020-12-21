// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2020 Renesas Inc.
// Copyright 2020 EPAM Systems Inc.
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

package identhandler

import (
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

/*******************************************************************************
 * Vars
 ******************************************************************************/

var plugins = make(map[string]NewPlugin)

/*******************************************************************************
 * Types
 ******************************************************************************/

// Handler identification handler
type Handler struct {
	sync.Mutex

	module IdentModule
}

// IdentModule identification module interface
type IdentModule interface {
	GetSystemID() (systemdID string, err error)
	GetUsers() (users []string, err error)
	SetUsers(users []string) (err error)
	UsersChangedChannel() (channel <-chan []string)
	Close() (err error)
}

// NewPlugin plugin new function
type NewPlugin func(configJSON json.RawMessage) (module IdentModule, err error)

/*******************************************************************************
 * Public
 ******************************************************************************/

// RegisterPlugin registers module plugin
func RegisterPlugin(plugin string, newFunc NewPlugin) {
	log.WithField("plugin", plugin).Info("Register identification plugin")

	plugins[plugin] = newFunc
}

// New returns pointer to new Handler
func New(cfg *config.Config) (handler *Handler, err error) {
	handler = &Handler{}

	log.Debug("Create identification handler")

	newModule, ok := plugins[cfg.Identifier.Plugin]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", cfg.Identifier.Plugin)
	}

	if handler.module, err = newModule(cfg.Identifier.Params); err != nil {
		return nil, err
	}

	return handler, nil
}

// Close closes identification handler
func (handler *Handler) Close() {
	log.Debug("Close identification handler")

	handler.module.Close()
}

// GetSystemID return system ID
func (handler *Handler) GetSystemID() (systemdID string, err error) {
	return handler.module.GetSystemID()
}

// GetUsers returns current users
func (handler *Handler) GetUsers() (users []string, err error) {
	return handler.module.GetUsers()
}

// SetUsers set current users
func (handler *Handler) SetUsers(users []string) (err error) {
	return handler.module.SetUsers(users)
}

// UsersChangedChannel returns users changed channel
func (handler *Handler) UsersChangedChannel() (channel <-chan []string) {
	return handler.module.UsersChangedChannel()
}

/*******************************************************************************
 * Private
 ******************************************************************************/
