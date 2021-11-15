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

	"aos_iamanager/config"
	"aos_iamanager/identhandler"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type testIdentifier struct {
	systemID            string
	boardModel          string
	users               []string
	usersChangedChannel chan []string
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var identifier = &testIdentifier{usersChangedChannel: make(chan []string, 1)}

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true})
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

	identifier.users = []string{"user1", "user2", "user3"}

	users, err := handler.GetUsers()
	if err != nil {
		t.Fatalf("Can't get users: %s", err)
	}

	if !reflect.DeepEqual(users, identifier.users) {
		t.Errorf("Wrong users: %v", users)
	}

	newUsers := []string{"newUser1", "newUser2", "newUser3"}

	if err = handler.SetUsers(newUsers); err != nil {
		t.Fatalf("Can't set users: %s", users)
	}

	if !reflect.DeepEqual(identifier.users, newUsers) {
		t.Errorf("Wrong users: %v", users)
	}

	select {
	case users := <-handler.UsersChangedChannel():
		if !reflect.DeepEqual(users, newUsers) {
			t.Errorf("Wrong users: %v", users)
		}

	case <-time.After(5 * time.Second):
		t.Error("Wait users changed timeout")
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

func (identifier *testIdentifier) Close() (err error) {
	return nil
}
