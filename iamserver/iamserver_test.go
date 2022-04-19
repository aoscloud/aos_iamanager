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
	"context"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/api/cloudprotocol"
	pb "github.com/aoscloud/aos_common/api/iamanager/v2"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/aoscloud/aos_iamanager/config"
	"github.com/aoscloud/aos_iamanager/iamserver"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	serverURL       = "localhost:8088"
	serverPublicURL = "localhost:8089"
)

const (
	certURLStr = "certURL"
	keyURLStr  = "keyURL"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

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
	systemID               string
	boardModel             string
	subjects               []string
	subjectsChangedChannel chan []string
}

type testPermissionHandler struct {
	permissions               map[string]map[string]map[string]string
	currentInstance           cloudprotocol.InstanceIdent
	registerError             error
	currentUnregisterInstance cloudprotocol.InstanceIdent
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

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

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

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

	response, err := client.pbPublic.GetCertTypes(ctx, &empty.Empty{})
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

	if response.Csr != string(certHandler.csr) {
		t.Errorf("Wrong CSR value: %s", response.Csr)
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

	certHandler.certURL = certURLStr

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

	certHandler.certURL = certURLStr
	certHandler.keyURL = keyURLStr

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	request := &pb.GetCertRequest{Type: "online", Issuer: []byte("issuer"), Serial: "serial"}

	response, err := client.pbPublic.GetCert(ctx, request)
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if response.Type != request.Type {
		t.Errorf("Wrong response type: %s", response.Type)
	}

	if response.CertUrl != certURLStr {
		t.Errorf("Wrong cert URL: %s", response.CertUrl)
	}

	if response.KeyUrl != keyURLStr {
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

func TestGetSubjects(t *testing.T) {
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

	identHandler.subjects = []string{"subject1", "subject2", "subject3"}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	response, err := client.pbPublic.GetSubjects(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	if !reflect.DeepEqual(response.Subjects, identHandler.subjects) {
		t.Errorf("Wrong subjects: %v", response.Subjects)
	}
}

func TestInstancePermissions(t *testing.T) {
	permHandler := testPermissionHandler{permissions: make(map[string]map[string]map[string]string)}

	server, err := iamserver.New(&config.Config{ServerURL: serverURL, ServerPublicURL: serverPublicURL},
		&testIdentHandler{}, &testCertHandler{}, &permHandler, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(serverURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var (
		testServiceID       = "serviceID1"
		expectedPermissions = map[string]map[string]string{
			"vis": {"*": "rw", "test": "r"},
		}
		funServerID     = "vis"
		setPBPermission = &pb.Permissions{Permissions: map[string]string{"*": "rw", "test": "r"}}
	)

	req := &pb.RegisterInstanceRequest{
		Instance:    &pb.InstanceIdent{ServiceId: testServiceID, SubjectId: "s1", Instance: 2},
		Permissions: map[string]*pb.Permissions{funServerID: setPBPermission},
	}

	resp, err := client.pbProtected.RegisterInstance(ctx, req)
	if err != nil {
		t.Fatalf("Can't request instance: %v", err)
	}

	if receivesPermission, ok := permHandler.permissions[resp.Secret]; ok {
		if !reflect.DeepEqual(receivesPermission, expectedPermissions) {
			t.Error("Incorrect requested permissions")
		}
	} else {
		t.Error("Permission is not received")
	}

	if resp.Secret == "" {
		t.Fatal("Incorrect secret")
	}

	getPBPermissions, err := client.pbPublic.GetPermissions(ctx,
		&pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: funServerID})
	if err != nil {
		t.Fatalf("Can't send get permission request: %v", err)
	}

	if !proto.Equal(getPBPermissions.Permissions, setPBPermission) {
		t.Error("Incorrect permission")
	}

	clientPublic, err := newTestClientPublic(serverPublicURL)
	if err != nil {
		t.Fatalf("Can't create test client: %s", err)
	}

	defer client.close()

	if getPBPermissions, err = clientPublic.pbPublic.GetPermissions(ctx,
		&pb.PermissionsRequest{Secret: resp.Secret, FunctionalServerId: funServerID}); err != nil {
		t.Fatalf("Can't send get permission request to public url: %v", err)
	}

	if !proto.Equal(getPBPermissions.Permissions, setPBPermission) {
		t.Error("Incorrect permission")
	}

	if _, err := client.pbPublic.GetPermissions(ctx,
		&pb.PermissionsRequest{Secret: "noSecret", FunctionalServerId: funServerID}); err == nil {
		t.Error("Should be error")
	}

	expectedUnregisterInstance := cloudprotocol.InstanceIdent{ServiceID: testServiceID, SubjectID: "s1", Instance: 2}

	if _, err := client.pbProtected.UnregisterInstance(ctx,
		&pb.UnregisterInstanceRequest{Instance: &pb.InstanceIdent{
			ServiceId: testServiceID, SubjectId: "s1", Instance: 2,
		}}); err != nil {
		t.Fatalf("Can't send unregister instance: %v", err)
	}

	if permHandler.currentUnregisterInstance != expectedUnregisterInstance {
		t.Error("Receive incorrect unregister instance")
	}

	permHandler.registerError = aoserrors.New("some error")

	if _, err := client.pbProtected.RegisterInstance(ctx, req); err == nil {
		t.Error("Should be error")
	}
}

func TestSubjectsChanged(t *testing.T) {
	identHandler := &testIdentHandler{subjectsChangedChannel: make(chan []string, 1)}

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

	stream, err := client.pbPublic.SubscribeSubjectsChanged(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %s", err)
	}

	time.Sleep(1 * time.Second)

	newSubjects := []string{"newSubject1", "newSubject2", "newSubject3"}

	identHandler.subjectsChangedChannel <- newSubjects

	var message *pb.Subjects

	if message, err = stream.Recv(); err != nil {
		t.Fatalf("Error receiving message: %s", err)
	}

	if !reflect.DeepEqual(message.Subjects, newSubjects) {
		t.Errorf("Wrong subjects: %v", message.Subjects)
	}
}

func TestGetAPIVersion(t *testing.T) {
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

	response, err := client.pbPublic.GetAPIVersion(context.Background(), &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't get api version: %s", err)
	}

	if response.Version != 2 {
		t.Errorf("Wrong api version: %v", response.Version)
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestClient(url string) (client *testClient, err error) { // nolint:unparam // param added for future purposes
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
	certURL, keyURL string, err error,
) {
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

func (handler *testIdentHandler) GetSubjects() (subjects []string, err error) {
	return handler.subjects, nil
}

func (handler *testIdentHandler) SubjectsChangedChannel() (channel <-chan []string) {
	return handler.subjectsChangedChannel
}

func (permission *testPermissionHandler) RegisterInstance(
	instance cloudprotocol.InstanceIdent, permissions map[string]map[string]string,
) (secret string, err error) {
	if permission.registerError != nil {
		return "", permission.registerError
	}

	secret = time.Now().String()

	permission.permissions[secret] = permissions
	permission.currentInstance = instance

	return secret, nil
}

func (permission *testPermissionHandler) UnregisterInstance(instance cloudprotocol.InstanceIdent) {
	permission.currentUnregisterInstance = instance
}

func (permission *testPermissionHandler) GetPermissions(
	secret, funcServerID string,
) (cloudprotocol.InstanceIdent, map[string]string, error) {
	allPermissions, ok := permission.permissions[secret]
	if !ok {
		return permission.currentInstance, nil, aoserrors.New("no permissions")
	}

	permissions, ok := allPermissions[funcServerID]
	if !ok {
		return permission.currentInstance, nil, aoserrors.New("no permissions")
	}

	return permission.currentInstance, permissions, nil
}
