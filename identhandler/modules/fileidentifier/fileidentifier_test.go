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
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/identhandler/modules/fileidentifier"
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
	subjectsFile := path.Join(tmpDir, "subjects.txt")

	systemID := "testSystemID"

	if err := writeID(systemIDFile, systemID); err != nil {
		t.Fatalf("Can't write system ID: %s", err)
	}

	if err := writeID(boardModelFile, ""); err != nil {
		t.Fatalf("Can't write boardModel: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, subjectsFile))
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
	subjectsFile := path.Join(tmpDir, "subjects.txt")

	boardModel := "testBoard:1.0"

	if err := writeID(boardModelFile, boardModel); err != nil {
		t.Fatalf("Can't write boardModel: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, subjectsFile))
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

func TestGetSubjects(t *testing.T) {
	systemIDFile := path.Join(tmpDir, "systemid.txt")
	boardModelFile := path.Join(tmpDir, "boardmodel.txt")
	subjectsFile := path.Join(tmpDir, "subjects.txt")

	if err := writeID(systemIDFile, "testSystemID"); err != nil {
		t.Fatalf("Can't write system ID: %s", err)
	}

	subjects := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	if err := writeSubjects(subjectsFile, subjects); err != nil {
		t.Fatalf("Can't write subjects: %s", err)
	}

	identifier, err := fileidentifier.New(generateConfig(systemIDFile, boardModelFile, subjectsFile))
	if err != nil {
		t.Fatalf("Can't create identifier: %s", err)
	}
	defer identifier.Close()

	getSubjects, err := identifier.GetSubjects()
	if err != nil {
		t.Fatalf("Error getting subjects: %s", err)
	}

	if !reflect.DeepEqual(getSubjects, subjects) {
		t.Errorf("Wrong subjects value: %v", getSubjects)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func generateConfig(systemIDPath, boardModelPath, subjectsPath string) (config []byte) {
	type adapterConfig struct {
		SystemIDPath   string `json:"systemIdPath"`
		BoardModelPath string `json:"boardModelPath"`
		SubjectsPath   string `json:"subjectsPath"`
	}

	var err error

	if config, err = json.Marshal(&adapterConfig{
		SystemIDPath:   systemIDPath,
		BoardModelPath: boardModelPath, SubjectsPath: subjectsPath,
	}); err != nil {
		log.Fatalf("Can't marshal config: %s", err)
	}

	return config
}

func writeSubjects(subjectsFile string, subjects []string) (err error) {
	file, err := os.Create(subjectsFile)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, claim := range subjects {
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
