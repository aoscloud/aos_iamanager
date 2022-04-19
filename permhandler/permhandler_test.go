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

package permhandler_test

import (
	"os"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_common/api/cloudprotocol"
	"github.com/aoscloud/aos_iamanager/permhandler"
)

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

func TestInstancePermissions(t *testing.T) {
	permissionHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permission handler: %v", err)
	}

	var (
		instanceIdent1        = cloudprotocol.InstanceIdent{ServiceID: "serviceID1", Instance: 1}
		instanceIdent2        = cloudprotocol.InstanceIdent{ServiceID: "serviceID1", Instance: 2}
		vis                   = map[string]string{"*": "rw", "test": "r"}
		systemCore            = map[string]string{"test1.*": "rw", "test2": "r"}
		funcServerPermissions = map[string]map[string]string{"vis": vis, "systemCore": systemCore}
	)

	secret1, err := permissionHandler.RegisterInstance(instanceIdent1, funcServerPermissions)
	if err != nil || secret1 == "" {
		t.Fatalf("Can't register instance: %v", err)
	}

	instance, perm, err := permissionHandler.GetPermissions(secret1, "vis")
	if err != nil {
		t.Fatalf("Can't get permissions: %v", err)
	}

	if instanceIdent1 != instance {
		t.Error("Wrong instance")
	}

	if !reflect.DeepEqual(perm, vis) {
		t.Errorf("Wrong perm: %v", perm)
	}

	secret2, err := permissionHandler.RegisterInstance(instanceIdent2, funcServerPermissions)
	if err != nil || secret1 == "" {
		t.Fatalf("Can't register instance: %v", err)
	}

	if secret1 == secret2 {
		t.Error("Duplicated secret for second registration")
	}

	if instance, perm, err = permissionHandler.GetPermissions(secret2, "systemCore"); err != nil {
		t.Fatalf("Can't get permissions: %v", err)
	}

	if instanceIdent2 != instance {
		t.Error("Wrong instance")
	}

	if !reflect.DeepEqual(perm, systemCore) {
		t.Errorf("Wrong perm: %v", perm)
	}

	if _, _, err = permissionHandler.GetPermissions(secret1, "functionalServerID"); err == nil {
		t.Fatalf("Wrong perm for functional server")
	}

	permissionHandler.UnregisterInstance(instanceIdent2)

	if _, _, err = permissionHandler.GetPermissions(secret1, "systemCore"); err != nil {
		t.Fatalf("Can't get permissions: %v", err)
	}

	permissionHandler.UnregisterInstance(instanceIdent1)

	if _, _, err = permissionHandler.GetPermissions(secret1, "systemCore"); err == nil {
		t.Fatalf("Getting permissions after the instance has been deleted")
	}

	permissionHandler.UnregisterInstance(instanceIdent2)
}
