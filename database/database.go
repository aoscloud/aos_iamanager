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

package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aoscloud/aos_common/aoserrors"
	_ "github.com/mattn/go-sqlite3" // ignore lint
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/certhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	dbVersion   = 1
	busyTimeout = 60000
	journalMode = "WAL"
	syncMode    = "NORMAL"
)

/*******************************************************************************
 * Vars
 ******************************************************************************/

// ErrVersionMismatch is returned when DB has unsupported DB version.
var ErrVersionMismatch = errors.New("version mismatch")

/*******************************************************************************
 * Types
 ******************************************************************************/

// Database structure with database information.
type Database struct {
	sql *sql.DB
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new database handle.
func New(name string) (db *Database, err error) {
	log.WithField("name", name).Debug("Open database")

	// Check and create db path
	if _, err = os.Stat(filepath.Dir(name)); err != nil {
		if !os.IsNotExist(err) {
			return db, aoserrors.Wrap(err)
		}

		if err = os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return db, aoserrors.Wrap(err)
		}
	}

	var sqlite *sql.DB

	if sqlite, err = sql.Open("sqlite3", fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_sync=%s",
		name, busyTimeout, journalMode, syncMode)); err != nil {
		return db, aoserrors.Wrap(err)
	}

	defer func() {
		if err != nil {
			sqlite.Close()
		}
	}()

	db = &Database{sqlite}

	if err = db.createConfigTable(); err != nil {
		return db, aoserrors.Wrap(err)
	}

	if err := db.createCertTable(); err != nil {
		return db, aoserrors.Wrap(err)
	}

	version, err := db.getVersion()
	if err != nil {
		return db, aoserrors.Wrap(err)
	}

	if version != dbVersion {
		return db, ErrVersionMismatch
	}

	return db, nil
}

// AddCertificate adds new certificate to database.
func (db *Database) AddCertificate(certType string, cert certhandler.CertInfo) (err error) {
	if _, err = db.sql.Exec("INSERT INTO certificates values(?, ?, ?, ?, ?, ?)",
		certType, cert.Issuer, cert.Serial, cert.CertURL, cert.KeyURL, cert.NotAfter); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// GetCertificate returns certificate by issuer and serial.
func (db *Database) GetCertificate(issuer, serial string) (cert certhandler.CertInfo, err error) {
	rows, err := db.sql.Query(
		"SELECT issuer, serial, certURL, keyURL, notAfter FROM certificates WHERE issuer = ? AND serial = ?",
		issuer, serial)
	if err != nil {
		return cert, aoserrors.Wrap(err)
	}
	defer rows.Close()

	if rows.Err() != nil {
		return cert, aoserrors.Wrap(rows.Err())
	}

	if rows.Next() {
		if err = rows.Scan(&cert.Issuer, &cert.Serial, &cert.CertURL, &cert.KeyURL, &cert.NotAfter); err != nil {
			return cert, aoserrors.Wrap(err)
		}

		return cert, nil
	}

	return cert, aoserrors.Wrap(certhandler.ErrNotExist)
}

// GetCertificates returns certificates of selected type.
func (db *Database) GetCertificates(certType string) (certs []certhandler.CertInfo, err error) {
	rows, err := db.sql.Query(
		"SELECT issuer, serial, certURL, keyURL, notAfter FROM certificates WHERE type = ?", certType)
	if err != nil {
		return certs, aoserrors.Wrap(err)
	}
	defer rows.Close()

	if rows.Err() != nil {
		return certs, aoserrors.Wrap(rows.Err())
	}

	for rows.Next() {
		var cert certhandler.CertInfo

		if err = rows.Scan(&cert.Issuer, &cert.Serial, &cert.CertURL, &cert.KeyURL, &cert.NotAfter); err != nil {
			return certs, aoserrors.Wrap(err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// RemoveCertificate removes certificate from database.
func (db *Database) RemoveCertificate(certType, certURL string) (err error) {
	if _, err = db.sql.Exec("DELETE FROM certificates WHERE type = ? AND certURL = ?", certType, certURL); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// RemoveAllCertificates removes all certificate from database.
func (db *Database) RemoveAllCertificates(certType string) (err error) {
	if _, err = db.sql.Exec("DELETE FROM certificates WHERE type = ?", certType); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// Close closes database.
func (db *Database) Close() {
	db.sql.Close()
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (db *Database) getVersion() (version uint64, err error) {
	stmt, err := db.sql.Prepare("SELECT version FROM config")
	if err != nil {
		return version, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&version)
	if err != nil {
		return version, aoserrors.Wrap(err)
	}

	return version, nil
}

func (db *Database) setVersion(version uint64) (err error) {
	result, err := db.sql.Exec("UPDATE config SET version = ?", version)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return aoserrors.New("row version not exist")
	}

	return nil
}

func (db *Database) isTableExist(name string) (result bool, err error) {
	rows, err := db.sql.Query("SELECT * FROM sqlite_master WHERE name = ? and type='table'", name)
	if err != nil {
		return false, aoserrors.Wrap(err)
	}
	defer rows.Close()

	result = rows.Next()

	return result, aoserrors.Wrap(rows.Err())
}

func (db *Database) createConfigTable() (err error) {
	log.Info("Create config table")

	exist, err := db.isTableExist("config")
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if exist {
		return nil
	}

	if _, err = db.sql.Exec(
		`CREATE TABLE config (
			version INTEGER)`); err != nil {
		return aoserrors.Wrap(err)
	}

	if _, err = db.sql.Exec(
		`INSERT INTO config (
			version) values(?)`, dbVersion); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (db *Database) createCertTable() (err error) {
	log.Info("Create cert table")

	if _, err = db.sql.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		type TEXT NOT NULL,
		issuer TEXT NOT NULL,
		serial TEXT NOT NULL,
		certURL TEXT,
		keyURL TEXT,
		notAfter TIMESTAMP,
		PRIMARY KEY (issuer, serial))`); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}
