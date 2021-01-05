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

package iamserver_test

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	pb "gitpct.epam.com/epmd-aepr/aos_common/api/iamanager"
	"google.golang.org/grpc"

	"aos_iamanager/config"
	"aos_iamanager/iamserver"
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
	pbclient   pb.IAManagerClient
}

type testCertHandler struct {
	certTypes []string
	csr       string
	certURL   string
	keyURL    string
	password  string
	err       error
}

type testIdentHandler struct {
	systemID            string
	users               []string
	usersChangedChannel chan []string
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

func TestGetCertTypes(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, &testIdentHandler{}, certHandler, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	certHandler.certTypes = []string{"test1", "test2", "test3"}

	response, err := client.pbclient.GetCertTypes(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(certHandler.certTypes, response.Types) {
		t.Errorf("Wrong cert types: %v", response.Types)
	}
}

func TestFinishProvisioning(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "iam_")
	if err != nil {
		log.Fatalf("Error creating temporary dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	finishFile := path.Join(tmpDir, "finish.sh")

	server, err := iamserver.New(&config.Config{
		ServerURL:                 serverURL,
		FinishProvisioningCmdArgs: []string{"touch", finishFile}}, &testIdentHandler{}, &testCertHandler{}, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if _, err = client.pbclient.FinishProvisioning(ctx, &empty.Empty{}); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if _, err = os.Stat(finishFile); err != nil {
		t.Errorf("Finish file error: %s", err)
	}
}

func TestSetOwner(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, &testIdentHandler{}, certHandler, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	password := "password"

	setOwnerReq := &pb.SetOwnerReq{Type: "online", Password: password}

	if _, err = client.pbclient.SetOwner(ctx, setOwnerReq); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if certHandler.password != password {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	clearReq := &pb.ClearReq{Type: "online"}

	if _, err = client.pbclient.Clear(ctx, clearReq); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if certHandler.password != "" {
		t.Errorf("Wrong password: %s", certHandler.password)
	}
}

func TestCreateKeys(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, &testIdentHandler{}, certHandler, true)
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
}

func TestApplyCert(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, &testIdentHandler{}, certHandler, true)
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
}

func TestGetCert(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, &testIdentHandler{}, certHandler, true)
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
}

func TestGetSystemID(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, identHandler, &testCertHandler{}, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	identHandler.systemID = "testSystemID"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	response, err := client.pbclient.GetSystemID(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.Id != identHandler.systemID {
		t.Errorf("Wrong systemd ID: %s", response.Id)
	}
}

func TestGetUsers(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, identHandler, &testCertHandler{}, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	identHandler.users = []string{"user1", "user2", "user3"}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	response, err := client.pbclient.GetUsers(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(response.Users, identHandler.users) {
		t.Errorf("Wrong users: %v", response.Users)
	}
}

func TestSetUsers(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, identHandler, &testCertHandler{}, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	identHandler.users = []string{"user1", "user2", "user3"}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.SetUsersReq{Users: []string{"newUser1", "newUser2", "newUser3"}}

	if _, err := client.pbclient.SetUsers(ctx, request); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(request.Users, identHandler.users) {
		t.Errorf("Wrong users: %v", identHandler.users)
	}
}

func TestUsersChanged(t *testing.T) {
	identHandler := &testIdentHandler{usersChangedChannel: make(chan []string, 1)}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL}, identHandler, &testCertHandler{}, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}
	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.pbclient.SubscribeUsersChanged(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	time.Sleep(1 * time.Second)

	newUsers := []string{"newUser1", "newUser2", "newUser3"}

	identHandler.usersChangedChannel <- newUsers

	var message *pb.UsersChangedNtf

	if message, err = stream.Recv(); err != nil {
		t.Fatalf("Error receiving message: %s", err)
	}

	if !reflect.DeepEqual(message.Users, newUsers) {
		t.Errorf("Wrong users: %v", message.Users)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func newTestClient(url string) (client *testClient, err error) {
	client = &testClient{}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	if client.connection, err = grpc.DialContext(ctx, url, grpc.WithInsecure(), grpc.WithBlock()); err != nil {
		return nil, err
	}

	client.pbclient = pb.NewIAManagerClient(client.connection)

	return client, nil
}

func (client *testClient) close() {
	if client.connection != nil {
		client.connection.Close()
	}
}

func (handler *testCertHandler) GetCertTypes() (certTypes []string) {
	return handler.certTypes
}

func (handler *testCertHandler) SetOwner(certType, password string) (err error) {
	handler.password = password

	return nil
}

func (handler *testCertHandler) Clear(certType string) (err error) {
	handler.password = ""

	return nil
}

func (handler *testCertHandler) CreateKeys(certType, password string) (csr string, err error) {
	return handler.csr, handler.err
}

func (handler *testCertHandler) ApplyCertificate(certType string, cert string) (certURL string, err error) {
	return handler.certURL, handler.err
}

func (handler *testCertHandler) GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error) {
	return handler.certURL, handler.keyURL, handler.err
}

func (handler *testIdentHandler) GetSystemID() (systemID string, err error) {
	return handler.systemID, nil
}

func (handler *testIdentHandler) GetUsers() (users []string, err error) {
	return handler.users, nil
}

func (handler *testIdentHandler) SetUsers(users []string) (err error) {
	handler.users = users

	return nil
}

func (handler *testIdentHandler) UsersChangedChannel() (channel <-chan []string) {
	return handler.usersChangedChannel
}
