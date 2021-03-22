// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2021 Renesas Inc.
// Copyright 2021 EPAM Systems Inc.
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

package permhandler_test

import (
	"os"
	"reflect"
	"testing"

	"aos_iamanager/permhandler"

	log "github.com/sirupsen/logrus"
)

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

func TestRegisterUnregisterService(t *testing.T) {
	permissionHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permission handler: %s", err)
	}

	serviceID1 := "serviceID1"
	serviceID2 := "serviceID2"

	funcServerPermissions := map[string]map[string]string{"vis": {"*": "rw", "test": "r"}}
	secret1, err := permissionHandler.RegisterService(serviceID1, funcServerPermissions)
	if err != nil || secret1 == "" {
		t.Fatalf("Can't register service: %s", err)
	}

	secret2, err := permissionHandler.RegisterService(serviceID1, funcServerPermissions)
	if err != nil || secret2 != secret1 {
		t.Fatalf("Can't register service: %s", err)
	}

	secret3, err := permissionHandler.RegisterService(serviceID2, funcServerPermissions)
	if err != nil || secret3 == "" {
		t.Fatalf("Can't register service: %s", err)
	}

	permissionHandler.UnregisterService(serviceID1)

	secret1, err = permissionHandler.RegisterService(serviceID1, funcServerPermissions)
	if err != nil || secret1 == "" {
		t.Fatalf("Can't register service: %s", err)
	}
}

func TestGetPermissions(t *testing.T) {
	permissionHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permission handler: %s", err)
	}

	serviceID1 := "serviceID1"

	vis := map[string]string{"*": "rw", "test": "r"}
	systemCore := map[string]string{"test1.*": "rw", "test2": "r"}

	funcServerPermissions := map[string]map[string]string{"vis": vis, "systemCore": systemCore}

	secret1, err := permissionHandler.RegisterService(serviceID1, funcServerPermissions)
	if err != nil || secret1 == "" {
		t.Fatalf("Can't register service: %s", err)
	}

	perm, err := permissionHandler.GetPermissions(secret1, "vis")
	if err != nil {
		t.Fatalf("Can't get permissions: %s", err)
	}

	if !reflect.DeepEqual(perm, vis) {
		t.Errorf("Wrong perm: %v", perm)
	}

	perm, err = permissionHandler.GetPermissions(secret1, "systemCore")
	if err != nil {
		t.Fatalf("Can't get permissions: %s", err)
	}

	if !reflect.DeepEqual(perm, systemCore) {
		t.Errorf("Wrong perm: %v", perm)
	}

	_, err = permissionHandler.GetPermissions(secret1, "functionalServerID")
	if err == nil {
		t.Fatalf("Wrong perm for functional server")
	}

	permissionHandler.UnregisterService(serviceID1)

	_, err = permissionHandler.GetPermissions(secret1, "systemCore")
	if err == nil {
		t.Fatalf("Getting permissions after the service has been deleted")
	}
}
