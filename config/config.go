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

// Package config provides set of API to provide aos configuration
package config

import (
	"encoding/json"
	"os"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// Config instance.
type Config struct {
	IAMPublicServerURL        string         `json:"iamPublicServerUrl"`
	IAMProtectedServerURL     string         `json:"iamProtectedServerUrl"`
	NodeID                    string         `json:"nodeId"`
	NodeType                  string         `json:"nodeType"`
	CACert                    string         `json:"caCert"`
	CertStorage               string         `json:"certStorage"`
	WorkingDir                string         `json:"workingDir"`
	CertModules               []ModuleConfig `json:"certModules"`
	FinishProvisioningCmdArgs []string       `json:"finishProvisioningCmdArgs"`
	DiskEncryptionCmdArgs     []string       `json:"diskEncryptionCmdArgs"`
	EnablePermissionsHandler  bool           `json:"enablePermissionsHandler"`
	Identifier                Identifier     `json:"identifier"`
	RemoteIAMs                []RemoteIAM    `json:"remoteIams"`
}

// Identifier identifier plugin parameters.
type Identifier struct {
	Plugin string          `json:"plugin"`
	Params json.RawMessage `json:"params"`
}

// RemoteIAM remote IAM parameters.
type RemoteIAM struct {
	NodeID         string            `json:"nodeId"`
	URL            string            `json:"url"`
	RequestTimeout aostypes.Duration `json:"requestTimeout"`
}

// ModuleConfig module configuration.
type ModuleConfig struct {
	ID               string          `json:"id"`
	Plugin           string          `json:"plugin"`
	Algorithm        string          `json:"algorithm"`
	MaxItems         int             `json:"maxItems"`
	ExtendedKeyUsage []string        `json:"extendedKeyUsage"`
	AlternativeNames []string        `json:"alternativeNames"`
	Disabled         bool            `json:"disabled"`
	SkipValidation   bool            `json:"skipValidation"`
	Params           json.RawMessage `json:"params"`
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new config object.
func New(fileName string) (config *Config, err error) {
	file, err := os.Open(fileName)
	if err != nil {
		return config, aoserrors.Wrap(err)
	}

	config = &Config{}

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(config); err != nil {
		return config, aoserrors.Wrap(err)
	}

	return config, nil
}
