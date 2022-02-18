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

package fileidentifier

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/identhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const subjectsChangedChannelSize = 1

/*******************************************************************************
 * Types
 ******************************************************************************/

// Instance vis identifier instance.
type Instance struct {
	sync.Mutex

	config                 instanceConfig
	subjectsChangedChannel chan []string

	systemID   string
	boardModel string
	subjects   []string
}

type instanceConfig struct {
	SystemIDPath   string `json:"systemIdPath"`
	BoardModelPath string `json:"boardModelPath"`
	SubjectsPath   string `json:"subjectsPath"`
}

/*******************************************************************************
 * init
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new file identifier instance.
func New(configJSON json.RawMessage) (identifier identhandler.IdentModule, err error) {
	log.Info("Create file identification instance")

	instance := &Instance{}

	if err = json.Unmarshal(configJSON, &instance.config); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	instance.subjectsChangedChannel = make(chan []string, subjectsChangedChannelSize)

	if instance.systemID, err = instance.readDataFromFile(instance.config.SystemIDPath); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if instance.boardModel, err = instance.readDataFromFile(instance.config.BoardModelPath); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if err = instance.readSubjects(); err != nil {
		log.Warnf("Can't read subjects: %s. Empty subjects will be used", err)
	}

	return instance, nil
}

// Close closes vis identifier instance.
func (instance *Instance) Close() (err error) {
	log.Info("Close file identification instance")

	return nil
}

// GetSystemID returns the system ID.
func (instance *Instance) GetSystemID() (systemID string, err error) {
	instance.Lock()
	defer instance.Unlock()

	log.WithField("systemID", instance.systemID).Debug("Get system ID")

	return instance.systemID, aoserrors.Wrap(err)
}

// GetBoardModel returns the board model.
func (instance *Instance) GetBoardModel() (boardModel string, err error) {
	instance.Lock()
	defer instance.Unlock()

	log.WithField("boardModel", instance.boardModel).Debug("Get board model")

	return instance.boardModel, aoserrors.Wrap(err)
}

// SetUsers sets the user claims.
func (instance *Instance) SetUsers(users []string) (err error) {
	instance.Lock()
	defer instance.Unlock()

	log.WithField("users", users).Debug("Set users")

	if reflect.DeepEqual(instance.subjects, users) {
		return nil
	}

	instance.subjects = users

	if len(instance.subjectsChangedChannel) != subjectsChangedChannelSize {
		instance.subjectsChangedChannel <- users
	}

	if err = instance.writeUsers(); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// GetSubjects returns the subjects.
func (instance *Instance) GetSubjects() (subjects []string, err error) {
	instance.Lock()
	defer instance.Unlock()

	log.WithField("subjects", instance.subjects).Debug("Get subjects")

	return instance.subjects, aoserrors.Wrap(err)
}

// SubjectsChangedChannel returns subjects changed channel.
func (instance *Instance) SubjectsChangedChannel() (channel <-chan []string) {
	return instance.subjectsChangedChannel
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (instance *Instance) readDataFromFile(path string) (data string, err error) {
	rawData, err := ioutil.ReadFile(path)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	data = strings.TrimSpace(string(rawData))

	return data, nil
}

func (instance *Instance) readSubjects() (err error) {
	instance.subjects = make([]string, 0)

	file, err := os.Open(instance.config.SubjectsPath)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		instance.subjects = append(instance.subjects, scanner.Text())
	}

	return nil
}

func (instance *Instance) writeUsers() (err error) {
	file, err := os.Create(instance.config.SubjectsPath)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, claim := range instance.subjects {
		fmt.Fprintln(writer, claim)
	}

	return aoserrors.Wrap(writer.Flush())
}
