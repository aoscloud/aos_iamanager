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

package identhandler

import (
	"encoding/json"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

/*******************************************************************************
 * Vars
 ******************************************************************************/

var plugins = make(map[string]NewPlugin) // nolint:gochecknoglobals

/*******************************************************************************
 * Types
 ******************************************************************************/

// Handler identification handler.
type Handler struct {
	sync.Mutex

	module IdentModule
}

// IdentModule identification module interface.
type IdentModule interface {
	GetSystemID() (systemdID string, err error)
	GetBoardModel() (boardModel string, err error)
	GetSubjects() (subjects []string, err error)
	SubjectsChangedChannel() (channel <-chan []string)
	SetUsers(users []string) (err error)
	Close() (err error)
}

// NewPlugin plugin new function.
type NewPlugin func(configJSON json.RawMessage) (module IdentModule, err error)

/*******************************************************************************
 * Public
 ******************************************************************************/

// RegisterPlugin registers module plugin.
func RegisterPlugin(plugin string, newFunc NewPlugin) {
	log.WithField("plugin", plugin).Info("Register identification plugin")

	plugins[plugin] = newFunc
}

// New returns pointer to new Handler.
func New(cfg *config.Config) (handler *Handler, err error) {
	handler = &Handler{}

	log.Debug("Create identification handler")

	newModule, ok := plugins[cfg.Identifier.Plugin]
	if !ok {
		return nil, aoserrors.Errorf("plugin %s not found", cfg.Identifier.Plugin)
	}

	if handler.module, err = newModule(cfg.Identifier.Params); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return handler, nil
}

// Close closes identification handler.
func (handler *Handler) Close() {
	log.Debug("Close identification handler")

	handler.module.Close()
}

// GetSystemID return system ID.
func (handler *Handler) GetSystemID() (systemdID string, err error) {
	if systemdID, err = handler.module.GetSystemID(); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return systemdID, nil
}

// GetBoardModel return board model.
func (handler *Handler) GetBoardModel() (boardModel string, err error) {
	if boardModel, err = handler.module.GetBoardModel(); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return boardModel, nil
}

// SetUsers set current users.
func (handler *Handler) SetUsers(users []string) (err error) {
	return aoserrors.Wrap(handler.module.SetUsers(users))
}

// GetSubjects returns current subjects.
func (handler *Handler) GetSubjects() (subjects []string, err error) {
	if subjects, err = handler.module.GetSubjects(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return subjects, nil
}

// SubjectsChangedChannel returns subjects changed channel.
func (handler *Handler) SubjectsChangedChannel() (channel <-chan []string) {
	return handler.module.SubjectsChangedChannel()
}

/*******************************************************************************
 * Private
 ******************************************************************************/
