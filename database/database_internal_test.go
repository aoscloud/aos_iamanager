// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Renesas Inc.
// Copyright 2019 EPAM Systems Inc.
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

package database

import (
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strconv"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"aos_iamanager/certhandler"
)

/*******************************************************************************
 * Variables
 ******************************************************************************/

var dbPath string

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	tmpDir, err := ioutil.TempDir("", "um_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	dbPath = path.Join(tmpDir, "test.db")

	ret := m.Run()

	if err = os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error deleting tmp dir: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestDBVersion(t *testing.T) {
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Can't create database: %s", err)
	}

	if err = db.setVersion(dbVersion - 1); err != nil {
		t.Errorf("Can't set database version: %s", err)
	}

	db.Close()

	db, err = New(dbPath)
	if err == nil {
		t.Error("Expect version mismatch error")
	} else if err != ErrVersionMismatch {
		t.Errorf("Can't create database: %s", err)
	}

	if err := os.RemoveAll(dbPath); err != nil {
		t.Fatalf("Can't remove database: %s", err)
	}

	db.Close()
}

func TestNewErrors(t *testing.T) {
	// Check MkdirAll in New statement
	db, err := New("/sys/rooooot/test.db")
	if err == nil {
		db.Close()
		t.Fatal("expecting error with no access rights")
	}

	//Trying to create test.db with no access rights
	//Check fail of the createConfigTable
	db, err = New("/sys/test.db")
	if err == nil {
		db.Close()
		t.Fatal("Expecting error with no access rights")
	}
}

func TestAddRemoveCertificate(t *testing.T) {
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Can't create database: %s", err)
	}
	defer db.Close()

	type testData struct {
		certType      string
		cert          certhandler.CertInfo
		errorExpected bool
	}

	data := []testData{
		testData{certType: "online", cert: certhandler.CertInfo{"issuer0", "s0", "certURL0", "keyURL0", time.Now().UTC()}, errorExpected: false},
		testData{certType: "online", cert: certhandler.CertInfo{"issuer0", "s0", "certURL0", "keyURL0", time.Now().UTC()}, errorExpected: true},
		testData{certType: "online", cert: certhandler.CertInfo{"issuer1", "s0", "certURL1", "keyURL1", time.Now().UTC()}, errorExpected: false},
		testData{certType: "online", cert: certhandler.CertInfo{"issuer1", "s0", "certURL1", "keyURL1", time.Now().UTC()}, errorExpected: true},
		testData{certType: "online", cert: certhandler.CertInfo{"issuer2", "s0", "certURL2", "keyURL2", time.Now().UTC()}, errorExpected: false}}

	// Add certificates

	for _, item := range data {
		if err = db.AddCertificate(item.certType, item.cert); err != nil && !item.errorExpected {
			t.Errorf("Can't add certificate: %s", err)
		}
	}

	// Get certificates

	for _, item := range data {
		cert, err := db.GetCertificate(item.cert.Issuer, item.cert.Serial)
		if err != nil && !item.errorExpected {
			t.Errorf("Can't get certificate: %s", err)

			continue
		}

		if item.errorExpected {
			continue
		}

		if !reflect.DeepEqual(cert, item.cert) {
			t.Errorf("Wrong cert info: %v", cert)
		}
	}

	// Remove certificates

	for _, item := range data {
		if err = db.RemoveCertificate(item.certType, item.cert.CertURL); err != nil && !item.errorExpected {
			t.Errorf("Can't remove certificate: %s", err)
		}

		if _, err = db.GetCertificate(item.certType, item.cert.CertURL); err == nil {
			t.Error("Certificate should be removed")
		}
	}
}

func TestGetCertificates(t *testing.T) {
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Can't create database: %s", err)
	}
	defer db.Close()

	data := [][]certhandler.CertInfo{
		[]certhandler.CertInfo{
			certhandler.CertInfo{"issuer0", "s0", "certURL0", "keyURL0", time.Now().UTC()},
			certhandler.CertInfo{"issuer0", "s1", "certURL1", "keyURL1", time.Now().UTC()},
			certhandler.CertInfo{"issuer0", "s2", "certURL2", "keyURL2", time.Now().UTC()},
			certhandler.CertInfo{"issuer0", "s3", "certURL3", "keyURL3", time.Now().UTC()},
			certhandler.CertInfo{"issuer0", "s4", "certURL4", "keyURL4", time.Now().UTC()},
		},
		[]certhandler.CertInfo{
			certhandler.CertInfo{"issuer1", "s0", "certURL0", "keyURL0", time.Now().UTC()},
			certhandler.CertInfo{"issuer1", "s1", "certURL1", "keyURL1", time.Now().UTC()},
			certhandler.CertInfo{"issuer1", "s2", "certURL2", "keyURL2", time.Now().UTC()},
		},
		[]certhandler.CertInfo{
			certhandler.CertInfo{"issuer2", "s0", "certURL0", "keyURL0", time.Now().UTC()},
			certhandler.CertInfo{"issuer2", "s1", "certURL1", "keyURL1", time.Now().UTC()},
			certhandler.CertInfo{"issuer2", "s2", "certURL2", "keyURL2", time.Now().UTC()},
			certhandler.CertInfo{"issuer2", "s3", "certURL3", "keyURL3", time.Now().UTC()},
		},
	}

	for i, items := range data {
		for _, cert := range items {
			if err = db.AddCertificate("cert"+strconv.Itoa(i), cert); err != nil {
				t.Errorf("Can't add certificate: %s", err)
			}
		}
	}

	for i, items := range data {
		certs, err := db.GetCertificates("cert" + strconv.Itoa(i))
		if err != nil {
			t.Errorf("Can't get certificates: %s", err)

			continue
		}

		if !reflect.DeepEqual(certs, items) {
			t.Error("Wrong certs data")

			continue
		}
	}
}
