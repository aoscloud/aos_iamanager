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

package iamserver_test

import (
	"aos_iamanager/config"
	"aos_iamanager/iamserver"
	"aos_iamanager/permhandler"
	"context"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v1"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	serverURL       = "localhost:8088"
	serverPublicURL = "localhost:8089"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

type testClient struct {
	connection       *grpc.ClientConn
	connectionPublic *grpc.ClientConn
	pbProtected      pb.IAMProtectedServiceClient
	pbPublic         pb.IAMPublicServiceClient
}

type testCertHandler struct {
	certTypes []string
	csr       []byte
	certURL   string
	keyURL    string
	password  string
	err       error
}

type testIdentHandler struct {
	systemID            string
	boardModel          string
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
		FullTimestamp:    true,
	})
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

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, certHandler, nil, true)
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

	response, err := client.pbProtected.GetCertTypes(ctx, &empty.Empty{})
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
		ServerPublicURL:           serverPublicURL,
		FinishProvisioningCmdArgs: []string{"touch", finishFile},
	}, &testIdentHandler{}, &testCertHandler{}, nil, true)
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

	if _, err = client.pbProtected.FinishProvisioning(ctx, &empty.Empty{}); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if _, err = os.Stat(finishFile); err != nil {
		t.Errorf("Finish file error: %s", err)
	}
}

func TestSetOwner(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, certHandler, nil, true)
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

	setOwnerReq := &pb.SetOwnerRequest{Type: "online", Password: password}

	if _, err = client.pbProtected.SetOwner(ctx, setOwnerReq); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if certHandler.password != password {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	clearReq := &pb.ClearRequest{Type: "online"}

	if _, err = client.pbProtected.Clear(ctx, clearReq); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if certHandler.password != "" {
		t.Errorf("Wrong password: %s", certHandler.password)
	}
}

func TestCreateKey(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, certHandler, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}

	defer client.close()

	certHandler.csr = []byte("this is csr")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.CreateKeyRequest{Type: "online"}

	response, err := client.pbProtected.CreateKey(ctx, request)
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

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, certHandler, nil, true)
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

	request := &pb.ApplyCertRequest{Type: "online"}

	response, err := client.pbProtected.ApplyCert(ctx, request)
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

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, certHandler, nil, true)
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

	request := &pb.GetCertRequest{Type: "online", Issuer: []byte("issuer"), Serial: "serial"}

	response, err := client.pbProtected.GetCert(ctx, request)
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

func TestGetSystemInfo(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		identHandler, &testCertHandler{}, nil, true)
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
	identHandler.boardModel = "testBoardModel:1.0"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	response, err := client.pbPublic.GetSystemInfo(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.SystemId != identHandler.systemID {
		t.Errorf("Wrong systemd ID: %s", response.SystemId)
	}

	if response.BoardModel != identHandler.boardModel {
		t.Errorf("Wrong board model: %s", response.BoardModel)
	}
}

func TestGetUsers(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		identHandler, &testCertHandler{}, nil, true)
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

	response, err := client.pbPublic.GetUsers(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(response.Users, identHandler.users) {
		t.Errorf("Wrong users: %v", response.Users)
	}
}

func TestSetUsers(t *testing.T) {
	identHandler := &testIdentHandler{}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		identHandler, &testCertHandler{}, nil, true)
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

	request := &pb.Users{Users: []string{"newUser1", "newUser2", "newUser3"}}

	if _, err := client.pbProtected.SetUsers(ctx, request); err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(request.Users, identHandler.users) {
		t.Errorf("Wrong users: %v", identHandler.users)
	}
}

func TestRegisterService(t *testing.T) {
	permHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permissions handler: %s", err)
	}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, &testCertHandler{}, permHandler, true)
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

	permission := &pb.Permissions{Permissions: map[string]string{"*": "rw", "test": "r"}}
	req := &pb.RegisterServiceRequest{ServiceId: "serviceID1", Permissions: map[string]*pb.Permissions{"vis": permission}}

	resp, err := client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if resp.Secret == "" {
		t.Fatal("Incorrect secret")
	}

	req = &pb.RegisterServiceRequest{ServiceId: "serviceID2", Permissions: map[string]*pb.Permissions{"vis": permission}}

	resp, err = client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if resp.Secret == "" {
		t.Fatal("Incorrect secret")
	}

	secretServiceID2 := resp.Secret

	req = &pb.RegisterServiceRequest{ServiceId: "serviceID2", Permissions: map[string]*pb.Permissions{"vis": permission}}

	resp, err = client.pbProtected.RegisterService(ctx, req)
	if err != nil || resp.Secret != secretServiceID2 {
		t.Fatalf("Can't send request: %s", err)
	}
}

func TestUnregisterService(t *testing.T) {
	permHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permissions handler: %s", err)
	}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, &testCertHandler{}, permHandler, true)
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

	permission := &pb.Permissions{Permissions: map[string]string{"*": "rw", "test": "r"}}
	req := &pb.RegisterServiceRequest{ServiceId: "serviceID", Permissions: map[string]*pb.Permissions{"vis": permission}}

	resp, err := client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	_, err = client.pbProtected.UnregisterService(ctx, &pb.UnregisterServiceRequest{ServiceId: "serviceID"})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	req = &pb.RegisterServiceRequest{ServiceId: "serviceID", Permissions: map[string]*pb.Permissions{"vis": permission}}

	resp2, err := client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if resp.Secret == resp2.Secret {
		t.Fatal("Secrets must be different")
	}
}

func TestGetPermissions(t *testing.T) {
	permHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permissions handler: %s", err)
	}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, &testCertHandler{}, permHandler, true)
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

	serviceID := "serviceID"
	vis := &pb.Permissions{Permissions: map[string]string{"*": "rw", "test": "r"}}
	req := &pb.RegisterServiceRequest{ServiceId: serviceID, Permissions: map[string]*pb.Permissions{"vis": vis}}

	resp, err := client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	reqPerm := &pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: "vis"}

	perm, err := client.pbPublic.GetPermissions(ctx, reqPerm)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(perm.Permissions.Permissions, vis.Permissions) {
		t.Fatalf("Wrong perm: received %v expected %v", perm, vis.Permissions)
	}

	if perm.ServiceId != serviceID {
		t.Fatalf("Wrong perm: received %v expected %v", perm, vis.Permissions)
	}

	_, err = client.pbProtected.UnregisterService(ctx, &pb.UnregisterServiceRequest{ServiceId: serviceID})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	reqPerm = &pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: "vis"}
	if _, err = client.pbPublic.GetPermissions(ctx, reqPerm); err == nil {
		t.Fatalf("Can't send request: %s", err)
	}
}

func TestGetPermissionsServerPublic(t *testing.T) {
	permHandler, err := permhandler.New()
	if err != nil {
		t.Fatalf("Can't create permissions handler: %s", err)
	}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, &testCertHandler{}, permHandler, true)
	if err != nil {
		t.Fatalf("Can't create test server: %s", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}

	defer client.close()

	clientPublic, err := newTestClientPublic(serverPublicURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}

	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	serviceID := "serviceID"
	vis := &pb.Permissions{Permissions: map[string]string{"*": "rw", "test": "r"}}
	req := &pb.RegisterServiceRequest{ServiceId: serviceID, Permissions: map[string]*pb.Permissions{"vis": vis}}

	resp, err := client.pbProtected.RegisterService(ctx, req)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	reqPerm := &pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: "vis"}

	perm, err := clientPublic.pbPublic.GetPermissions(ctx, reqPerm)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(perm.Permissions.Permissions, vis.Permissions) {
		t.Fatalf("Wrong perm: received %v expected %v", perm, vis.Permissions)
	}

	if perm.ServiceId != serviceID {
		t.Fatalf("Wrong perm: received %v expected %v", perm, vis.Permissions)
	}

	_, err = client.pbProtected.UnregisterService(ctx, &pb.UnregisterServiceRequest{ServiceId: serviceID})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	reqPerm = &pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: "vis"}
	if _, err = clientPublic.pbPublic.GetPermissions(ctx, reqPerm); err == nil {
		t.Fatalf("Can't send request: %s", err)
	}
}

func TestUsersChanged(t *testing.T) {
	identHandler := &testIdentHandler{usersChangedChannel: make(chan []string, 1)}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		identHandler, &testCertHandler{}, nil, true)
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

	stream, err := client.pbPublic.SubscribeUsersChanged(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	time.Sleep(1 * time.Second)

	newUsers := []string{"newUser1", "newUser2", "newUser3"}

	identHandler.usersChangedChannel <- newUsers

	var message *pb.Users

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if client.connection, err = grpc.DialContext(ctx, url, grpc.WithInsecure(), grpc.WithBlock()); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	client.pbProtected = pb.NewIAMProtectedServiceClient(client.connection)
	client.pbPublic = pb.NewIAMPublicServiceClient(client.connection)

	return client, nil
}

func newTestClientPublic(url string) (client *testClient, err error) {
	client = &testClient{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if client.connectionPublic, err = grpc.DialContext(ctx, url, grpc.WithInsecure(), grpc.WithBlock()); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	client.pbPublic = pb.NewIAMPublicServiceClient(client.connectionPublic)

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

func (handler *testCertHandler) CreateKey(certType, password string) (csr []byte, err error) {
	return handler.csr, handler.err
}

func (handler *testCertHandler) ApplyCertificate(certType string, cert []byte) (certURL string, err error) {
	return handler.certURL, handler.err
}

func (handler *testCertHandler) GetCertificate(certType string, issuer []byte, serial string) (
	certURL, keyURL string, err error) {
	return handler.certURL, handler.keyURL, handler.err
}

func (handler *testCertHandler) CreateSelfSignedCert(certType, password string) (err error) {
	return nil
}

func (handler *testIdentHandler) GetSystemID() (systemID string, err error) {
	return handler.systemID, nil
}

func (handler *testIdentHandler) GetBoardModel() (boardModel string, err error) {
	return handler.boardModel, nil
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
