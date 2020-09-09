// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2020 Renesas Inc.
// Copyright 2020 EPAM Systems Inc.
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

package cmserver_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	pb "gitpct.epam.com/epmd-aepr/aos_common/api/certificatemanager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"aos_certificatemanager/cmserver"
	"aos_certificatemanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const serverURL = "localhost:8088"

/*******************************************************************************
 * Types
 ******************************************************************************/

type testClient struct {
	connection *grpc.ClientConn
	pbclient   pb.CertificateManagerClient
}

type testCertHandler struct {
	csr     string
	certURL string
	keyURL  string
	err     error
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

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

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestCreateKeys(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := cmserver.New(
		&config.Config{ServerURL: serverURL, Cert: "../data/cert.pem", Key: "../data/key.pem"},
		certHandler)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	certHandler.csr = "this is csr"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.CreateKeysReq{Type: "online"}

	response, err := client.pbclient.CreateKeys(ctx, request)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.Type != request.Type {
		t.Errorf("Wrong response type: %s", response.Type)
	}

	if string(response.Csr) != string(certHandler.csr) {
		t.Errorf("Wrong CSR value: %s", string(response.Csr))
	}

	if response.Error != "" {
		t.Errorf("Response error: %s", response.Error)
	}
}

func TestApplyCert(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := cmserver.New(
		&config.Config{ServerURL: serverURL, Cert: "../data/cert.pem", Key: "../data/key.pem"},
		certHandler)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	certHandler.certURL = "certURL"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.ApplyCertReq{Type: "online"}

	response, err := client.pbclient.ApplyCert(ctx, request)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.Type != request.Type {
		t.Errorf("Wrong response type: %s", response.Type)
	}

	if response.CertUrl != certHandler.certURL {
		t.Errorf("Wrong cert URL: %s", response.CertUrl)
	}

	if response.Error != "" {
		t.Errorf("Response error: %s", response.Error)
	}

}

func TestGetCert(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := cmserver.New(
		&config.Config{ServerURL: serverURL, Cert: "../data/cert.pem", Key: "../data/key.pem"},
		certHandler)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	certHandler.certURL = "certURL"
	certHandler.keyURL = "keyURL"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.GetCertReq{Type: "online", Issuer: []byte("issuer"), Serial: "serial"}

	response, err := client.pbclient.GetCert(ctx, request)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.Type != request.Type {
		t.Errorf("Wrong response type: %s", response.Type)
	}

	if response.CertUrl != "certURL" {
		t.Errorf("Wrong cert URL: %s", response.CertUrl)
	}

	if response.KeyUrl != "keyURL" {
		t.Errorf("Wrong key URL: %s", response.KeyUrl)
	}

	if response.Error != "" {
		t.Errorf("Response error: %s", response.Error)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func createServerConfig(serverAddress string) (cfg config.Config) {
	configJSON := `{
	"Cert": "../data/cert.pem",
	"Key":  "../data/key.pem"
}`

	if err := json.NewDecoder(strings.NewReader(configJSON)).Decode(&cfg); err != nil {
		log.Fatalf("Can't parse config: %s", err)
	}

	cfg.ServerURL = serverAddress

	return cfg
}

func newTestClient(url string) (client *testClient, err error) {
	client = &testClient{}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	if client.connection, err = grpc.DialContext(ctx, url,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithBlock()); err != nil {
		return nil, err
	}

	client.pbclient = pb.NewCertificateManagerClient(client.connection)

	return client, nil
}

func (client *testClient) close() {
	if client.connection != nil {
		client.connection.Close()
	}
}

func (handler *testCertHandler) CreateKeys(certType, systemID, password string) (csr string, err error) {
	return handler.csr, handler.err
}

func (handler *testCertHandler) ApplyCertificate(certType string, cert string) (certURL string, err error) {
	return handler.certURL, handler.err
}

func (handler *testCertHandler) GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error) {
	return handler.certURL, handler.keyURL, handler.err
}
