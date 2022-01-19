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

	"github.com/aoscloud/aos_iamanager/certhandler"
	"github.com/aoscloud/aos_iamanager/config"
	"github.com/aoscloud/aos_iamanager/database"
	"github.com/aoscloud/aos_iamanager/iamserver"
	"github.com/aoscloud/aos_iamanager/identhandler"
	"github.com/aoscloud/aos_iamanager/permhandler"

	_ "github.com/aoscloud/aos_iamanager/certhandler/modules"
	_ "github.com/aoscloud/aos_iamanager/identhandler/modules"
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

type iaManager struct {
	db                 *database.Database
	identHandler       *identhandler.Handler
	certHandler        *certhandler.Handler
	permissionsHandler *permhandler.Handler
	server             *iamserver.Server
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
 * IAManager
 ******************************************************************************/

func newIAManger(cfg *config.Config) (iam *iaManager, err error) {
	defer func() {
		if err != nil {
			iam.close()
			iam = nil
		}
	}()

	iam = &iaManager{}

	// Create DB
	dbFile := path.Join(cfg.WorkingDir, dbFileName)

	iam.db, err = database.New(dbFile)
	if err != nil {
		if errors.Is(err, database.ErrVersionMismatch) {
			log.Warning("Unsupported database version")
			cleanup(dbFile)
			iam.db, err = database.New(dbFile)
		}

		if err != nil {
			return iam, aoserrors.Wrap(err)
		}
	}

	iam.identHandler, err = identhandler.New(cfg)
	if err != nil {
		return iam, aoserrors.Wrap(err)
	}

	systemID, err := iam.identHandler.GetSystemID()
	if err != nil {
		return iam, aoserrors.Wrap(err)
	}

	iam.certHandler, err = certhandler.New(systemID, cfg, iam.db)
	if err != nil {
		return iam, aoserrors.Wrap(err)
	}

	iam.permissionsHandler, err = permhandler.New()
	if err != nil {
		log.Errorf("Can't create permissions handler: %s", err)
	}

	iam.server, err = iamserver.New(cfg, iam.identHandler, iam.certHandler, iam.permissionsHandler, false)
	if err != nil {
		return iam, aoserrors.Wrap(err)
	}

	return iam, nil
}

func (iam *iaManager) close() {
	if iam.db != nil {
		iam.db.Close()
	}

	if iam.identHandler != nil {
		iam.identHandler.Close()
	}

	if iam.certHandler != nil {
		iam.certHandler.Close()
	}

	if iam.server != nil {
		iam.server.Close()
	}
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

func main() {
	// Initialize command line flags
	configFile := flag.String("c", "aos_iamanager.cfg", "path to config file")
	strLogLevel := flag.String("v", "info", `log level: "debug", "info", "warn", "error", "fatal", "panic"`)
	useJournal := flag.Bool("j", false, "output logs to systemd journal")
	showVersion := flag.Bool("version", false, `show iamanager version`)

	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("Version: %s\n", GitSummary) // nolint:forbidigo // logs aren't initialized
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
		// Config is important to make CM works properly. If we can't parse the config no reason to continue.
		// If the error is temporary CM will be restarted by systemd.
		log.Fatalf("Can't parse config: %s", err)
	}

	iam, err := newIAManger(cfg)
	if err != nil {
		log.Fatalf("Can't create IAM: %s", err)
	}

	defer iam.close()

	// Notify systemd
	if _, err = daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Errorf("Can't notify systemd: %s", err)
	}

	// Handle SIGTERM
	terminateChannel := make(chan os.Signal, 1)
	signal.Notify(terminateChannel, os.Interrupt, syscall.SIGTERM)

	<-terminateChannel
}
