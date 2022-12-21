// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2022 Renesas Electronics Corporation.
// Copyright (C) 2022 EPAM Systems, Inc.
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

package iamclient_test

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/aoscloud/aos_iamanager/config"
	"github.com/aoscloud/aos_iamanager/iamclient"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const serverURL = "localhost:8089"

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type testServer struct {
	pb.UnimplementedIAMCertificateServiceServer
	pb.UnimplementedIAMProvisioningServiceServer

	certTypes    map[string][]string
	password     string
	provFinished bool
	csr          []byte
	certURL      string
	subject      string
	grpcServer   *grpc.Server
	certSerial   string
}

/***********************************************************************************************************************
 * Var
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
 * Tests
 **********************************************************************************************************************/

func TestGetNodesAndCertTypes(t *testing.T) {
	testServer, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer testServer.close()

	testServer.certTypes = map[string][]string{
		"node1": {"cert1", "cert2"},
		"node2": {"cert3", "cert4"},
		"node3": {"cert5", "cert6"},
	}

	remoteIAMs := []config.RemoteIAM{
		{NodeID: "node1", URL: serverURL},
		{NodeID: "node2", URL: serverURL},
		{NodeID: "node3", URL: serverURL},
	}

	testClient, err := iamclient.New(&config.Config{RemoteIAMs: remoteIAMs}, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer testClient.Close()

	expectedNodes := make([]string, 0, len(remoteIAMs))

	for _, iam := range remoteIAMs {
		expectedNodes = append(expectedNodes, iam.NodeID)
	}

	nodes := testClient.GetRemoteNodes()

	sort.Strings(nodes)
	sort.Strings(expectedNodes)

	if !reflect.DeepEqual(nodes, expectedNodes) {
		t.Errorf("Wrong connected nodes: %v", nodes)
	}

	for _, nodeID := range expectedNodes {
		certTypes, err := testClient.GetCertTypes(nodeID)
		if err != nil {
			t.Fatalf("Can't get cert types: %v", err)
		}

		if !reflect.DeepEqual(certTypes, testServer.certTypes[nodeID]) {
			t.Errorf("Wrong cert types: %v", certTypes)
		}
	}
}

func TestSetOwnerClear(t *testing.T) {
	testServer, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer testServer.close()

	testServer.certTypes = map[string][]string{"node1": {"cert1", "cert2"}}

	testClient, err := iamclient.New(&config.Config{RemoteIAMs: []config.RemoteIAM{
		{NodeID: "node1", URL: serverURL},
	}}, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer testClient.Close()

	password := uuid.New().String()

	if err := testClient.SetOwner("node1", "cert1", password); err != nil {
		t.Fatalf("Can't set owner: %v", err)
	}

	if testServer.password != password {
		t.Errorf("Wrong password: %s", testServer.password)
	}

	if err := testClient.Clear("node1", "cert1"); err != nil {
		t.Fatalf("Can't clear: %v", err)
	}

	if testServer.password != "" {
		t.Errorf("Wrong password: %s", testServer.password)
	}
}

func TestEncryptFinish(t *testing.T) {
	testServer, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer testServer.close()

	testServer.certTypes = map[string][]string{"node1": {"cert1", "cert2"}}

	testClient, err := iamclient.New(&config.Config{RemoteIAMs: []config.RemoteIAM{
		{NodeID: "node1", URL: serverURL},
	}}, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer testClient.Close()

	password := uuid.New().String()

	if err := testClient.EncryptDisk("node1", password); err != nil {
		t.Fatalf("Can't encrypt disk: %v", err)
	}

	if testServer.password != password {
		t.Errorf("Wrong password: %s", testServer.password)
	}

	if err := testClient.FinishProvisioning("node1"); err != nil {
		t.Fatalf("Can't finish provisioning: %v", err)
	}

	if !testServer.provFinished {
		t.Error("Provisioning not finished")
	}
}

func TestCreateKeyCert(t *testing.T) {
	testServer, err := newTestServer(serverURL)
	if err != nil {
		t.Fatalf("Can't create test server: %v", err)
	}

	defer testServer.close()

	testServer.certTypes = map[string][]string{"node1": {"cert1", "cert2"}}

	testClient, err := iamclient.New(&config.Config{RemoteIAMs: []config.RemoteIAM{
		{NodeID: "node1", URL: serverURL},
	}}, nil, nil, true)
	if err != nil {
		t.Fatalf("Can't create test client: %v", err)
	}

	defer testClient.Close()

	password := uuid.New().String()
	subject := uuid.New().String()
	testServer.csr = []byte(uuid.New().String())

	csr, err := testClient.CreateKey("node1", "cert1", subject, password)
	if err != nil {
		t.Fatalf("Can't create key: %v", err)
	}

	if testServer.password != password {
		t.Errorf("Wrong password: %s", testServer.password)
	}

	if testServer.subject != subject {
		t.Errorf("Wrong subject: %s", testServer.subject)
	}

	if string(csr) != string(testServer.csr) {
		t.Errorf("Wrong CSR: %s", string(csr))
	}

	certURL, serial, err := testClient.ApplyCertificate("node1", "cert1", []byte("certificate"))
	if err != nil {
		t.Fatalf("Can't apply certificate: %v", err)
	}

	if certURL != testServer.certURL {
		t.Errorf("Wrong cert URL: %s", certURL)
	}

	if serial != testServer.certSerial {
		t.Errorf("Wrong cert serial: %s", serial)
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newTestServer(serverURL string) (*testServer, error) {
	server := &testServer{
		certTypes:  make(map[string][]string),
		certSerial: "superCertificateSerial",
	}

	listener, err := net.Listen("tcp", serverURL)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	server.grpcServer = grpc.NewServer()

	pb.RegisterIAMProvisioningServiceServer(server.grpcServer, server)
	pb.RegisterIAMCertificateServiceServer(server.grpcServer, server)

	go func() {
		if err := server.grpcServer.Serve(listener); err != nil {
			log.Errorf("Can't serve grpc server: %s", err)
		}
	}()

	return server, nil
}

func (server *testServer) close() {
	if server.grpcServer != nil {
		server.grpcServer.Stop()
	}
}

func (server *testServer) GetCertTypes(ctx context.Context, request *pb.GetCertTypesRequest) (*pb.CertTypes, error) {
	certTypes, err := server.getCertTypes(request.NodeId)
	if err != nil {
		return &pb.CertTypes{}, err
	}

	return &pb.CertTypes{Types: certTypes}, nil
}

func (server *testServer) SetOwner(ctx context.Context, request *pb.SetOwnerRequest) (*empty.Empty, error) {
	if err := server.checkCertTypes(request.NodeId, request.Type); err != nil {
		return &empty.Empty{}, err
	}

	server.password = request.Password

	return &empty.Empty{}, nil
}

func (server *testServer) Clear(ctx context.Context, request *pb.ClearRequest) (*empty.Empty, error) {
	if err := server.checkCertTypes(request.NodeId, request.Type); err != nil {
		return &empty.Empty{}, err
	}

	server.password = ""

	return &empty.Empty{}, nil
}

func (server *testServer) EncryptDisk(ctx context.Context, request *pb.EncryptDiskRequest) (*empty.Empty, error) {
	if err := server.checkNode(request.NodeId); err != nil {
		return &empty.Empty{}, err
	}

	server.password = request.Password

	return &empty.Empty{}, nil
}

func (server *testServer) FinishProvisioning(ctx context.Context, request *empty.Empty) (*empty.Empty, error) {
	server.provFinished = true

	return &empty.Empty{}, nil
}

func (server *testServer) CreateKey(ctx context.Context, request *pb.CreateKeyRequest) (*pb.CreateKeyResponse, error) {
	response := &pb.CreateKeyResponse{NodeId: request.NodeId, Type: request.Type}

	if err := server.checkCertTypes(request.NodeId, request.Type); err != nil {
		return response, err
	}

	server.subject = request.Subject
	server.password = request.Password
	response.Csr = string(server.csr)

	return response, nil
}

func (server *testServer) ApplyCert(ctx context.Context, request *pb.ApplyCertRequest) (*pb.ApplyCertResponse, error) {
	response := &pb.ApplyCertResponse{NodeId: request.NodeId, Type: request.Type}

	if err := server.checkCertTypes(request.NodeId, request.Type); err != nil {
		return response, err
	}

	response.CertUrl = server.certURL
	response.Serial = server.certSerial

	return response, nil
}

func (server *testServer) getCertTypes(nodeID string) ([]string, error) {
	certTypes, ok := server.certTypes[nodeID]
	if !ok {
		return nil, errNodeNotFound
	}

	return certTypes, nil
}

func (server *testServer) checkNode(nodeID string) error {
	if _, ok := server.certTypes[nodeID]; !ok {
		return errNodeNotFound
	}

	return nil
}

func (server *testServer) checkCertTypes(nodeID string, certType string) error {
	certTypes, ok := server.certTypes[nodeID]
	if !ok {
		return errNodeNotFound
	}

	for _, existingCertType := range certTypes {
		if certType == existingCertType {
			return nil
		}
	}

	return errCertTypeNotFound
}
