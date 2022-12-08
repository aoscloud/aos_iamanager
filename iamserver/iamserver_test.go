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
	"errors"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aoscloud/aos_iamanager/config"
	"github.com/aoscloud/aos_iamanager/iamserver"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	publicServerURL    = "localhost:8088"
	protectedServerURL = "localhost:8089"
)

const testNodeID = "testNodeID"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testClient struct {
	connection *grpc.ClientConn
}

type testCertHandler struct {
	certTypes []string
	subject   string
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
	currentSecret             string
	currentRegisterInstance   aostypes.InstanceIdent
	currentUnregisterInstance aostypes.InstanceIdent
	registerError             error
}

type testRemoteIAMsHandler struct {
	nodesCertTypes       map[string][]string
	password             string
	subject              string
	csr                  []byte
	certURL              string
	diskEncrypted        map[string]bool
	provisioningFinished map[string]bool
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var (
	errNodeNotFound     = errors.New("node not found")
	errCertTypeNotFound = errors.New("cert type not found")
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

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestPublicService(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{
		PublicServerURL:    publicServerURL,
		ProtectedServerURL: protectedServerURL,
		NodeID:             testNodeID,
	},
		nil, certHandler, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(publicServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	publicService := pb.NewIAMPublicServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetAPIVersion

	apiResponse, err := publicService.GetAPIVersion(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if apiResponse.Version != 4 {
		t.Errorf("Wrong API version received: %d", apiResponse.Version)
	}

	// GetNodeID

	nodeResponse, err := publicService.GetNodeID(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if nodeResponse.NodeId != testNodeID {
		t.Errorf("Wrong node ID received: %s", nodeResponse.NodeId)
	}

	// GetCert

	certHandler.certURL = "certURL"
	certHandler.keyURL = "keyURL"

	certRequest := &pb.GetCertRequest{Type: "online", Issuer: []byte("issuer"), Serial: "serial"}

	certResponse, err := publicService.GetCert(ctx, certRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certResponse.Type != certRequest.Type {
		t.Errorf("Wrong response type: %s", certResponse.Type)
	}

	if certResponse.CertUrl != certHandler.certURL {
		t.Errorf("Wrong cert URL: %s", certResponse.CertUrl)
	}

	if certResponse.KeyUrl != certHandler.keyURL {
		t.Errorf("Wrong key URL: %s", certResponse.KeyUrl)
	}
}

func TestPublicIdentityService(t *testing.T) {
	identHandler := &testIdentHandler{subjectsChangedChannel: make(chan []string, 1)}

	server, err := iamserver.New(&config.Config{
		PublicServerURL:    publicServerURL,
		ProtectedServerURL: protectedServerURL,
	},
		nil, &testCertHandler{}, identHandler, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(publicServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	identityService := pb.NewIAMPublicIdentityServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetSystemInfo

	identHandler.systemID = "testSystemID"
	identHandler.boardModel = "testBoardModel:1.0"

	systemResponse, err := identityService.GetSystemInfo(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if systemResponse.SystemId != identHandler.systemID {
		t.Errorf("Wrong systemd ID: %s", systemResponse.SystemId)
	}

	if systemResponse.BoardModel != identHandler.boardModel {
		t.Errorf("Wrong board model: %s", systemResponse.BoardModel)
	}

	// GetSubjects

	identHandler.subjects = []string{"subject1", "subject2", "subject3"}

	subjectsResponse, err := identityService.GetSubjects(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if !reflect.DeepEqual(subjectsResponse.Subjects, identHandler.subjects) {
		t.Errorf("Wrong subjects: %v", subjectsResponse.Subjects)
	}

	// SubscribeSubjectsChanged

	stream, err := identityService.SubscribeSubjectsChanged(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	time.Sleep(1 * time.Second)

	newSubjects := []string{"newSubject1", "newSubject2", "newSubject3"}

	identHandler.subjectsChangedChannel <- newSubjects

	var message *pb.Subjects

	subjectsNotification, err := stream.Recv()
	if err != nil {
		t.Fatalf("Error receiving message: %v", err)
	}

	if !reflect.DeepEqual(subjectsNotification.Subjects, newSubjects) {
		t.Errorf("Wrong subjects: %v", message.Subjects)
	}
}

func TestPermissionsService(t *testing.T) {
	permissionHandler := &testPermissionHandler{
		permissions: make(map[string]map[string]map[string]string),
	}

	server, err := iamserver.New(&config.Config{
		PublicServerURL:    publicServerURL,
		ProtectedServerURL: protectedServerURL,
	},
		nil, &testCertHandler{}, nil, permissionHandler, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(protectedServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	permissionsService := pb.NewIAMPermissionsServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	registerRequest := &pb.RegisterInstanceRequest{
		Instance:    &pb.InstanceIdent{ServiceId: "testService", SubjectId: "testSubject", Instance: 2},
		Permissions: map[string]*pb.Permissions{"testServer": {Permissions: map[string]string{"*": "rw", "test": "r"}}},
	}

	// RegisterInstance

	registerResponse, err := permissionsService.RegisterInstance(ctx, registerRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	receivedPermissions, ok := permissionHandler.permissions[registerResponse.Secret]
	if !ok {
		t.Error("Permission is not received")
	}

	if !reflect.DeepEqual(receivedPermissions["testServer"], registerRequest.Permissions["testServer"].Permissions) {
		t.Errorf("Incorrect requested permissions: %v", receivedPermissions["testServer"])
	}

	if registerResponse.Secret != permissionHandler.currentSecret {
		t.Errorf("Incorrect secret: %v", registerResponse.Secret)
	}

	// GetPermissions

	publicPermissionsService := pb.NewIAMPublicPermissionsServiceClient(client.connection)

	permissionsResponse, err := publicPermissionsService.GetPermissions(ctx,
		&pb.PermissionsRequest{Secret: registerResponse.Secret, FunctionalServerId: "testServer"})
	if err != nil {
		t.Fatalf("Can't send get permission request: %v", err)
	}

	if !reflect.DeepEqual(permissionsResponse.Permissions.Permissions,
		registerRequest.Permissions["testServer"].Permissions) {
		t.Errorf("Incorrect requested permissions: %v", permissionsResponse.Permissions.Permissions)
	}

	if permissionsResponse.Instance.String() != registerRequest.Instance.String() {
		t.Errorf("Incorrect instance ident: %v", permissionsResponse.Instance.String())
	}

	// UnregisterInstance

	unregisterRequest := &pb.UnregisterInstanceRequest{
		Instance: &pb.InstanceIdent{ServiceId: "testService", SubjectId: "testSubject", Instance: 1},
	}

	if _, err := permissionsService.UnregisterInstance(ctx, unregisterRequest); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	expectedInstanceIdent := aostypes.InstanceIdent{
		ServiceID: unregisterRequest.Instance.ServiceId,
		SubjectID: unregisterRequest.Instance.SubjectId,
		Instance:  unregisterRequest.Instance.Instance,
	}

	if permissionHandler.currentUnregisterInstance != expectedInstanceIdent {
		t.Errorf("Incorrect instance ident: %v", permissionHandler.currentUnregisterInstance)
	}

	// RegisterInstance error

	permissionHandler.registerError = aoserrors.New("some error")

	if _, err := permissionsService.RegisterInstance(ctx, registerRequest); err == nil {
		t.Error("Error expected")
	}
}

func TestProvisioningService(t *testing.T) {
	certHandler := &testCertHandler{}

	tmpDir, err := ioutil.TempDir("", "iam_")
	if err != nil {
		log.Fatalf("Error creating temporary dir: %v", err)
	}

	defer os.RemoveAll(tmpDir)

	encryptDiskFile := path.Join(tmpDir, "encrypt.sh")
	finishProvisioningFile := path.Join(tmpDir, "finish.sh")

	server, err := iamserver.New(&config.Config{
		PublicServerURL:           publicServerURL,
		ProtectedServerURL:        protectedServerURL,
		NodeID:                    testNodeID,
		DiskEncryptionCmdArgs:     []string{"touch", encryptDiskFile},
		FinishProvisioningCmdArgs: []string{"touch", finishProvisioningFile},
	},
		nil, certHandler, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(protectedServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	provisioningService := pb.NewIAMProvisioningServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetAllNodeIDs

	nodeIDsResponse, err := provisioningService.GetAllNodeIDs(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if !reflect.DeepEqual(nodeIDsResponse.Ids, []string{testNodeID}) {
		t.Errorf("Wrong node ID's: %v", nodeIDsResponse.Ids)
	}

	// GetCertTypes

	certHandler.certTypes = []string{"test1", "test2", "test3"}

	certTypesResponse, err := provisioningService.GetCertTypes(ctx, &pb.GetCertTypesRequest{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if !reflect.DeepEqual(certTypesResponse.Types, certHandler.certTypes) {
		t.Errorf("Wrong nide ID's: %v", nodeIDsResponse.Ids)
	}

	// SetOwner

	password := "password"

	setOwnerReq := &pb.SetOwnerRequest{Type: "online", Password: password}

	if _, err = provisioningService.SetOwner(ctx, setOwnerReq); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certHandler.password != password {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	// Clear

	clearReq := &pb.ClearRequest{Type: "online"}

	if _, err = provisioningService.Clear(ctx, clearReq); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certHandler.password != "" {
		t.Errorf("Wrong password: %s", certHandler.password)
	}

	// EncryptDisk

	if _, err = provisioningService.EncryptDisk(ctx, &pb.EncryptDiskRequest{Password: password}); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if _, err = os.Stat(encryptDiskFile); err != nil {
		t.Errorf("Encrypt disk file error: %v", err)
	}

	// FinishProvisioning

	if _, err = provisioningService.FinishProvisioning(ctx, &empty.Empty{}); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if _, err = os.Stat(finishProvisioningFile); err != nil {
		t.Errorf("Finish provisioning file error: %v", err)
	}
}

func TestCertificateService(t *testing.T) {
	certHandler := &testCertHandler{}

	server, err := iamserver.New(&config.Config{
		PublicServerURL:    publicServerURL,
		ProtectedServerURL: protectedServerURL,
	},
		nil, certHandler, &testIdentHandler{systemID: "testSystem"}, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(protectedServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	certificateService := pb.NewIAMCertificateServiceClient(client.connection)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// CreateKey

	certHandler.csr = []byte("this is csr")

	createKeyRequest := &pb.CreateKeyRequest{Type: "online"}

	createKeyResponse, err := certificateService.CreateKey(ctx, createKeyRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if createKeyResponse.Type != createKeyRequest.Type {
		t.Errorf("Wrong response type: %s", createKeyResponse.Type)
	}

	if createKeyResponse.Csr != string(certHandler.csr) {
		t.Errorf("Wrong CSR value: %s", createKeyResponse.Csr)
	}

	// ApplyCertificate

	certificateRequest := &pb.ApplyCertRequest{Type: "online"}

	certificateResponse, err := certificateService.ApplyCert(ctx, certificateRequest)
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	if certificateResponse.Type != certificateRequest.Type {
		t.Errorf("Wrong response type: %s", certificateResponse.Type)
	}

	if certificateResponse.CertUrl != certHandler.certURL {
		t.Errorf("Wrong cert URL: %s", certificateResponse.CertUrl)
	}
}

func TestRemoteIAMs(t *testing.T) {
	certHandler := &testCertHandler{}
	remoteIAMsHandler := &testRemoteIAMsHandler{}

	server, err := iamserver.New(&config.Config{
		PublicServerURL:    publicServerURL,
		ProtectedServerURL: protectedServerURL,
		NodeID:             testNodeID,
	},
		nil, certHandler, nil, nil, remoteIAMsHandler, true)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}
	defer server.Close()

	client, err := newTestClient(protectedServerURL)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer client.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certHandler.certTypes = []string{"certType1", "certType2"}

	remoteIAMsHandler.nodesCertTypes = map[string][]string{
		"node1": {"certType3", "certType4"},
		"node2": {"certType5", "certType6"},
		"node3": {"certType7", "certType8"},
	}

	// GetRemoteNodes

	provisioningService := pb.NewIAMProvisioningServiceClient(client.connection)
	certificateService := pb.NewIAMCertificateServiceClient(client.connection)

	nodeIDsResponse, err := provisioningService.GetAllNodeIDs(ctx, &empty.Empty{})
	if err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	expectedNodes := []string{testNodeID}

	for node := range remoteIAMsHandler.nodesCertTypes {
		expectedNodes = append(expectedNodes, node)
	}

	sort.Strings(expectedNodes)
	sort.Strings(nodeIDsResponse.Ids)

	if !reflect.DeepEqual(nodeIDsResponse.Ids, expectedNodes) {
		t.Errorf("Wrong node IDs: %v", nodeIDsResponse.Ids)
	}

	// GetCertTypes

	expectedCertTypes := make(map[string][]string)

	expectedCertTypes[testNodeID] = certHandler.certTypes

	for key, value := range remoteIAMsHandler.nodesCertTypes {
		expectedCertTypes[key] = value
	}

	for _, node := range expectedNodes {
		certTypesResponse, err := provisioningService.GetCertTypes(ctx, &pb.GetCertTypesRequest{NodeId: node})
		if err != nil {
			t.Fatalf("Can't send request: %v", err)
		}

		if !reflect.DeepEqual(expectedCertTypes[node], certTypesResponse.Types) {
			t.Errorf("Wrong cert types: %v, node: %s", certTypesResponse.Types, node)
		}

		// Clear

		for _, certType := range certTypesResponse.Types {
			if node == testNodeID {
				certHandler.password = uuid.New().String()
			} else {
				remoteIAMsHandler.password = uuid.New().String()
			}

			if _, err := provisioningService.Clear(ctx, &pb.ClearRequest{NodeId: node, Type: certType}); err != nil {
				t.Fatalf("Can't send request: %v", err)
			}

			if node == testNodeID {
				if certHandler.password != "" {
					t.Errorf("Wrong cert storage password: %s", certHandler.password)
				}
			} else {
				if remoteIAMsHandler.password != "" {
					t.Errorf("Wrong cert storage password: %s", remoteIAMsHandler.password)
				}
			}
		}

		// SetOwner

		for _, certType := range certTypesResponse.Types {
			password := uuid.New().String()

			if _, err := provisioningService.SetOwner(ctx, &pb.SetOwnerRequest{
				NodeId: node, Type: certType, Password: password,
			}); err != nil {
				t.Fatalf("Can't send request: %v", err)
			}

			if node == testNodeID {
				if certHandler.password != password {
					t.Errorf("Wrong cert storage password: %s", certHandler.password)
				}
			} else {
				if remoteIAMsHandler.password != password {
					t.Errorf("Wrong cert storage password: %s", remoteIAMsHandler.password)
				}
			}
		}

		// CreateKey

		for _, certType := range certTypesResponse.Types {
			csr := uuid.New().String()
			subject := uuid.New().String()

			if node == testNodeID {
				certHandler.csr = []byte(csr)
			} else {
				remoteIAMsHandler.csr = []byte(csr)
			}

			keyResponse, err := certificateService.CreateKey(
				ctx, &pb.CreateKeyRequest{NodeId: node, Subject: subject, Type: certType})
			if err != nil {
				t.Fatalf("Can't send request: %v", err)
			}

			if node == testNodeID {
				if certHandler.subject != subject {
					t.Errorf("Wrong subject: %s", certHandler.subject)
				}
			} else {
				if remoteIAMsHandler.subject != subject {
					t.Errorf("Wrong subject: %s", remoteIAMsHandler.subject)
				}
			}

			if keyResponse.Csr != csr {
				t.Errorf("Wrong CSR: %s", err)
			}
		}

		// ApplyCertificate

		for _, certType := range certTypesResponse.Types {
			certURL := uuid.New().String()

			if node == testNodeID {
				certHandler.certURL = certURL
			} else {
				remoteIAMsHandler.certURL = certURL
			}

			certResponse, err := certificateService.ApplyCert(
				ctx, &pb.ApplyCertRequest{NodeId: node, Type: certType, Cert: "certificate"})
			if err != nil {
				t.Fatalf("Can't send request: %v", err)
			}

			if node == testNodeID {
				if certHandler.certURL != certResponse.CertUrl {
					t.Errorf("Wrong cert URL: %s", certHandler.certURL)
				}
			} else {
				if remoteIAMsHandler.certURL != certResponse.CertUrl {
					t.Errorf("Wrong cert URL: %s", remoteIAMsHandler.certURL)
				}
			}
		}

		// EncryptDisk

		password := uuid.New().String()

		remoteIAMsHandler.diskEncrypted = make(map[string]bool)

		if _, err := provisioningService.EncryptDisk(ctx, &pb.EncryptDiskRequest{
			NodeId: node, Password: password,
		}); err != nil {
			t.Fatalf("Can't send request: %v", err)
		}

		if node == testNodeID {
			continue
		}

		if remoteIAMsHandler.password != password {
			t.Errorf("Wrong password: %s", remoteIAMsHandler.password)
		}

		if !remoteIAMsHandler.diskEncrypted[node] {
			t.Errorf("Disk on node %s not encrypted", node)
		}
	}

	// FinishProvisioning

	remoteIAMsHandler.provisioningFinished = make(map[string]bool)

	if _, err := provisioningService.FinishProvisioning(ctx, &empty.Empty{}); err != nil {
		t.Fatalf("Can't send request: %v", err)
	}

	for _, node := range expectedNodes {
		if node == testNodeID {
			continue
		}

		if !remoteIAMsHandler.provisioningFinished[node] {
			t.Errorf("Provisioning on node %s not finished", node)
		}
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestClient(url string) (client *testClient, err error) {
	client = &testClient{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if client.connection, err = grpc.DialContext(
		ctx, url, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()); err != nil {
		return nil, aoserrors.Wrap(err)
	}

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

func (handler *testCertHandler) CreateKey(certType, subject, password string) (csr []byte, err error) {
	handler.subject = subject

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

func (handler *testPermissionHandler) RegisterInstance(
	instance aostypes.InstanceIdent, permissions map[string]map[string]string,
) (secret string, err error) {
	if handler.registerError != nil {
		return "", handler.registerError
	}

	handler.currentSecret = time.Now().String()
	handler.permissions[handler.currentSecret] = permissions
	handler.currentRegisterInstance = instance

	return handler.currentSecret, nil
}

func (handler *testPermissionHandler) UnregisterInstance(instance aostypes.InstanceIdent) {
	handler.currentUnregisterInstance = instance
}

func (handler *testPermissionHandler) GetPermissions(
	secret, funcServerID string,
) (aostypes.InstanceIdent, map[string]string, error) {
	allPermissions, ok := handler.permissions[secret]
	if !ok {
		return handler.currentRegisterInstance, nil, aoserrors.New("no permissions")
	}

	permissions, ok := allPermissions[funcServerID]
	if !ok {
		return handler.currentRegisterInstance, nil, aoserrors.New("no permissions")
	}

	return handler.currentRegisterInstance, permissions, nil
}

func (handler *testRemoteIAMsHandler) GetRemoteNodes() []string {
	nodes := make([]string, 0, len(handler.nodesCertTypes))

	for node := range handler.nodesCertTypes {
		nodes = append(nodes, node)
	}

	return nodes
}

func (handler *testRemoteIAMsHandler) GetCertTypes(nodeID string) ([]string, error) {
	certTypes, ok := handler.nodesCertTypes[nodeID]
	if !ok {
		return nil, errNodeNotFound
	}

	return certTypes, nil
}

func (handler *testRemoteIAMsHandler) SetOwner(nodeID, certType, password string) error {
	certTypes, ok := handler.nodesCertTypes[nodeID]
	if !ok {
		return errNodeNotFound
	}

	for _, existingCertType := range certTypes {
		if existingCertType == certType {
			handler.password = password

			return nil
		}
	}

	return errCertTypeNotFound
}

func (handler *testRemoteIAMsHandler) Clear(nodeID, certType string) error {
	certTypes, ok := handler.nodesCertTypes[nodeID]
	if !ok {
		return errNodeNotFound
	}

	for _, existingCertType := range certTypes {
		if existingCertType == certType {
			handler.password = ""

			return nil
		}
	}

	return errCertTypeNotFound
}

func (handler *testRemoteIAMsHandler) CreateKey(nodeID, certType, subject, password string) (csr []byte, err error) {
	certTypes, ok := handler.nodesCertTypes[nodeID]
	if !ok {
		return nil, errNodeNotFound
	}

	for _, existingCertType := range certTypes {
		if existingCertType == certType {
			handler.subject = subject

			return handler.csr, nil
		}
	}

	return nil, errCertTypeNotFound
}

func (handler *testRemoteIAMsHandler) ApplyCertificate(
	nodeID, certType string, cert []byte,
) (certURL string, err error) {
	certTypes, ok := handler.nodesCertTypes[nodeID]
	if !ok {
		return "", errNodeNotFound
	}

	for _, existingCertType := range certTypes {
		if existingCertType == certType {
			return handler.certURL, nil
		}
	}

	return "", errCertTypeNotFound
}

func (handler *testRemoteIAMsHandler) EncryptDisk(nodeID, password string) error {
	handler.diskEncrypted[nodeID] = true
	handler.password = password

	return nil
}

func (handler *testRemoteIAMsHandler) FinishProvisioning(nodeID string) error {
	handler.provisioningFinished[nodeID] = true

	return nil
}
