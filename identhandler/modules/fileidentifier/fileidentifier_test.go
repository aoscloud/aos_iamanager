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

package fileidentifier_test

import (
	"aos_iamanager/identhandler/modules/fileidentifier"
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

/*******************************************************************************
 * Vars
 ******************************************************************************/

var tmpDir string

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
	var err error

	tmpDir, err = ioutil.TempDir("", "vis_")
	if err != nil {
		log.Fatalf("Error creating tmp dir: %s", err)
	}

	ret := m.Run()

	if err := os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing tmp dir: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestGetSystemID(t *testing.T) {
	systemIDFile := path.Join(tmpDir, "systemid.txt")
	boardModelFile := path.Join(tmpDir, "boardmodel.txt")
	usersFile := path.Join(tmpDir, "users.txt")

	systemID := "testSystemID"

	if err := writeID(systemIDFile, systemID); err != nil {
		t.Fatalf("Can't write system ID: %s", err)
	}

	if err := writeID(boardModelFile, ""); err != nil {
		t.Fatalf("Can't write boardModel: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, usersFile))
	if err != nil {
		t.Fatalf("Can't create identifier: %s", err)
	}
	defer identifier.Close()

	getSystemID, err := identifier.GetSystemID()
	if err != nil {
		t.Fatalf("Error getting system ID: %s", err)
	}

	if getSystemID != systemID {
		t.Errorf("Wrong system ID value: %s", getSystemID)
	}
}

func TestGetBoardModel(t *testing.T) {
	systemIDFile := path.Join(tmpDir, "systemid.txt")
	boardModelFile := path.Join(tmpDir, "boardmodel.txt")
	usersFile := path.Join(tmpDir, "users.txt")

	boardModel := "testBoard:1.0"

	if err := writeID(boardModelFile, boardModel); err != nil {
		t.Fatalf("Can't write boardModel: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, usersFile))
	if err != nil {
		t.Fatalf("Can't create identifier: %s", err)
	}
	defer identifier.Close()

	getBoardModel, err := identifier.GetBoardModel()
	if err != nil {
		t.Fatalf("Error getting system ID: %s", err)
	}

	if getBoardModel != boardModel {
		t.Errorf("Wrong board model value: %s", getBoardModel)
	}
}

func TestGetUsers(t *testing.T) {
	systemIDFile := path.Join(tmpDir, "systemid.txt")
	boardModelFile := path.Join(tmpDir, "boardmodel.txt")
	usersFile := path.Join(tmpDir, "users.txt")

	if err := writeID(systemIDFile, "testSystemID"); err != nil {
		t.Fatalf("Can't write system ID: %s", err)
	}

	users := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	if err := writeUsers(usersFile, users); err != nil {
		t.Fatalf("Can't write users: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, usersFile))
	if err != nil {
		t.Fatalf("Can't create identifier: %s", err)
	}
	defer identifier.Close()

	getUsers, err := identifier.GetUsers()
	if err != nil {
		t.Fatalf("Error getting users: %s", err)
	}

	if !reflect.DeepEqual(getUsers, users) {
		t.Errorf("Wrong users value: %v", getUsers)
	}
}

func TestSetUsers(t *testing.T) {
	systemIDFile := path.Join(tmpDir, "systemid.txt")
	boardModelFile := path.Join(tmpDir, "boardmodel.txt")
	usersFile := path.Join(tmpDir, "users.txt")

	if err := writeID(systemIDFile, "testSystemID"); err != nil {
		t.Fatalf("Can't write system ID: %s", err)
	}

	if err := writeUsers(usersFile, []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}); err != nil {
		t.Fatalf("Can't write users: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, usersFile))
	if err != nil {
		t.Fatalf("Can't create identifier: %s", err)
	}
	defer identifier.Close()

	newUsers := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	if err := identifier.SetUsers(newUsers); err != nil {
		t.Fatalf("Error setting users: %s", err)
	}

	select {
	case users := <-identifier.UsersChangedChannel():
		if !reflect.DeepEqual(newUsers, users) {
			t.Errorf("Wrong users value: %s", users)
		}

	case <-time.After(5 * time.Second):
		t.Error("Waiting for users changed timeout")
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func generateConfig(systemIDPath, boardModelPath, usersPath string) (config []byte) {
	type adapterConfig struct {
		SystemIDPath   string `json:"systemIdPath"`
		BoardModelPath string `json:"boardModelPath"`
		UsersPath      string `json:"usersPath"`
	}

	var err error

	if config, err = json.Marshal(&adapterConfig{
		SystemIDPath:   systemIDPath,
		BoardModelPath: boardModelPath, UsersPath: usersPath,
	}); err != nil {
		log.Fatalf("Can't marshal config: %s", err)
	}

	return config
}

func writeUsers(usersFile string, users []string) (err error) {
	file, err := os.Create(usersFile)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, claim := range users {
		fmt.Fprintln(writer, claim)
	}

	if err = writer.Flush(); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func writeID(filePth string, id string) (err error) {
	if err = ioutil.WriteFile(filePth, []byte(id), 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}
