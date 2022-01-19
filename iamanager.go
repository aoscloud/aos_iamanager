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

package main

import (
	"aos_iamanager/certhandler"
	"aos_iamanager/config"
	"aos_iamanager/database"
	"aos_iamanager/iamserver"
	"aos_iamanager/identhandler"
	"aos_iamanager/permhandler"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/coreos/go-systemd/daemon"
	"github.com/coreos/go-systemd/journal"
	log "github.com/sirupsen/logrus"

	_ "aos_iamanager/certhandler/modules"

	_ "aos_iamanager/identhandler/modules"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const dbFileName = "iamanager.db"

/*******************************************************************************
 * Vars
 ******************************************************************************/

// GitSummary provided by govvv at compile-time.
var GitSummary string // nolint:gochecknoglobals

/*******************************************************************************
 * Types
 ******************************************************************************/

type journalHook struct {
	severityMap map[log.Level]journal.Priority
}

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func cleanup(dbFile string) {
	log.Debug("System cleanup")

	log.WithField("file", dbFile).Debug("Delete DB file")

	if err := os.RemoveAll(dbFile); err != nil {
		log.Fatalf("Can't cleanup database: %s", err)
	}
}

func newJournalHook() (hook *journalHook) {
	hook = &journalHook{
		severityMap: map[log.Level]journal.Priority{
			log.DebugLevel: journal.PriDebug,
			log.InfoLevel:  journal.PriInfo,
			log.WarnLevel:  journal.PriWarning,
			log.ErrorLevel: journal.PriErr,
			log.FatalLevel: journal.PriCrit,
			log.PanicLevel: journal.PriEmerg,
		},
	}

	return hook
}

func (hook *journalHook) Fire(entry *log.Entry) (err error) {
	if entry == nil {
		return aoserrors.New("log entry is nil")
	}

	logMessage, err := entry.String()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	err = journal.Print(hook.severityMap[entry.Level], logMessage)

	return aoserrors.Wrap(err)
}

func (hook *journalHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func main() { // nolint:funlen
	// Initialize command line flags
	configFile := flag.String("c", "aos_iamanager.cfg", "path to config file")
	strLogLevel := flag.String("v", "info", `log level: "debug", "info", "warn", "error", "fatal", "panic"`)
	useJournal := flag.Bool("j", false, "output logs to systemd journal")
	showVersion := flag.Bool("version", false, `show iamanager version`)

	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("Version: %s\n", GitSummary)
		return
	}

	if *useJournal {
		log.AddHook(newJournalHook())
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Set log level
	logLevel, err := log.ParseLevel(*strLogLevel)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	log.SetLevel(logLevel)

	log.WithFields(log.Fields{"configFile": *configFile, "version": GitSummary}).Info("Start IAM")

	cfg, err := config.New(*configFile)
	if err != nil {
		log.Fatalf("Can't open config file: %s", err)
	}

	// Create DB
	dbFile := path.Join(cfg.WorkingDir, dbFileName)

	db, err := database.New(dbFile)
	if err != nil {
		if errors.Is(err, database.ErrVersionMismatch) {
			log.Warning("Unsupported database version")
			cleanup(dbFile)
			db, err = database.New(dbFile)
		}

		if err != nil {
			log.Fatalf("Can't create database: %s", err)
		}
	}
	defer db.Close()

	identHandler, err := identhandler.New(cfg)
	if err != nil {
		log.Fatalf("Can't create ident handler: %s", err)
	}
	defer identHandler.Close()

	systemID, err := identHandler.GetSystemID()
	if err != nil {
		log.Fatalf("Can't get system ID: %s", err)
	}

	certHandler, err := certhandler.New(systemID, cfg, db)
	if err != nil {
		log.Fatalf("Can't create cert handler: %s", err)
	}
	defer certHandler.Close()

	permissionsHandler, err := permhandler.New()
	if err != nil {
		log.Fatalf("Can't create permissions handler: %s", err)
	}

	server, err := iamserver.New(cfg, identHandler, certHandler, permissionsHandler, false)
	if err != nil {
		log.Fatalf("Can't create IAM server: %s", err)
	}
	defer server.Close()

	// Notify systemd
	if _, err = daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Errorf("Can't notify systemd: %s", err)
	}

	// Handle SIGTERM
	terminateChannel := make(chan os.Signal, 1)
	signal.Notify(terminateChannel, os.Interrupt, syscall.SIGTERM)

	<-terminateChannel
}
