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

package identhandler_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/config"
	"github.com/aoscloud/aos_iamanager/identhandler"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type testIdentifier struct {
	systemID               string
	boardModel             string
	subjects               []string
	subjectsChangedChannel chan []string
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var identifier = &testIdentifier{subjectsChangedChannel: make(chan []string, 1)}

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	identhandler.RegisterPlugin("testidentifier", newTestIdentifier)

	ret := m.Run()

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestIdentifier(t *testing.T) {
	handler, err := identhandler.New(&config.Config{Identifier: struct {
		Plugin string          `json:"plugin"`
		Params json.RawMessage `json:"params"`
	}{Plugin: "testidentifier"}})
	if err != nil {
		t.Fatalf("Can't create identification handler: %s", err)
	}
	defer handler.Close()

	identifier.systemID = "testID"

	systemID, err := handler.GetSystemID()
	if err != nil {
		t.Fatalf("Can't get system ID: %s", err)
	}

	if systemID != identifier.systemID {
		t.Errorf("Wrong system ID: %s", systemID)
	}

	identifier.boardModel = "testBoard:1.0"

	boardModel, err := handler.GetBoardModel()
	if err != nil {
		t.Fatalf("Can't get system ID: %s", err)
	}

	if boardModel != identifier.boardModel {
		t.Errorf("Wrong system ID: %s", boardModel)
	}

	identifier.subjects = []string{"subject1", "subject2", "subject3"}

	subjects, err := handler.GetSubjects()
	if err != nil {
		t.Fatalf("Can't get subject: %s", err)
	}

	if !reflect.DeepEqual(subjects, identifier.subjects) {
		t.Errorf("Wrong subject: %v", subjects)
	}

	newSubjects := []string{"newSubject1", "newSubject2", "newSubject3"}

	if err = identifier.ChangeSubjects(newSubjects); err != nil {
		t.Fatalf("Can't set subjects: %s", newSubjects)
	}

	select {
	case subjects := <-handler.SubjectsChangedChannel():
		if !reflect.DeepEqual(subjects, newSubjects) {
			t.Errorf("Wrong subjects: %v", subjects)
		}

	case <-time.After(5 * time.Second):
		t.Error("Wait subjects changed timeout")
	}
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

func newTestIdentifier(configJSON json.RawMessage) (module identhandler.IdentModule, err error) {
	return identifier, nil
}

func (identifier *testIdentifier) GetSystemID() (systemdID string, err error) {
	return identifier.systemID, nil
}

func (identifier *testIdentifier) GetBoardModel() (boardModel string, err error) {
	return identifier.boardModel, nil
}

func (identifier *testIdentifier) GetUsers() (users []string, err error) {
	return identifier.users, nil
}

func (identifier *testIdentifier) SetUsers(users []string) (err error) {
	identifier.users = users

	identifier.usersChangedChannel <- users

	return nil
}

func (identifier *testIdentifier) UsersChangedChannel() (channel <-chan []string) {
	return identifier.usersChangedChannel
}

func (identifier *testIdentifier) GetSubjects() (subjects []string, err error) {
	return identifier.subjects, nil
}

func (identifier *testIdentifier) ChangeSubjects(subjects []string) (err error) {
	identifier.subjects = subjects

	identifier.subjectsChangedChannel <- subjects

	return nil
}

func (identifier *testIdentifier) SubjectsChangedChannel() (channel <-chan []string) {
	return identifier.subjectsChangedChannel
}

func (identifier *testIdentifier) Close() (err error) {
	return nil
}
