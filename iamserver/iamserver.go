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

package iamserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"os/exec"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/api/cloudprotocol"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/aoscloud/aos_iamanager/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const discEncryptionType = "diskencryption"

const iamAPIVersion = 4

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Server IAM server instance.
type Server struct {
	sync.Mutex
	pb.UnimplementedIAMPublicServiceServer
	pb.UnimplementedIAMPublicIdentityServiceServer
	pb.UnimplementedIAMPublicPermissionsServiceServer
	pb.UnimplementedIAMProvisioningServiceServer
	pb.UnimplementedIAMCertificateServiceServer
	pb.UnimplementedIAMPermissionsServiceServer

	cryptoContext     *cryptutils.CryptoContext
	certHandler       CertHandler
	identHandler      IdentHandler
	permissionHandler PermissionHandler
	remoteIAMsHandler RemoteIAMsHandler

	publicListener            net.Listener
	protectedListener         net.Listener
	grpcPublicServer          *grpc.Server
	grpcProtectedServer       *grpc.Server
	subjectsChangedStreams    []pb.IAMPublicIdentityService_SubscribeSubjectsChangedServer
	nodeID                    string
	finishProvisioningCmdArgs []string
	diskEncryptCmdArgs        []string

	cancelFunction context.CancelFunc
}

// RemoteIAMsHandler remote IAM's handler.
type RemoteIAMsHandler interface {
	GetRemoteNodes() []string
	GetCertTypes(nodeID string) ([]string, error)
	SetOwner(nodeID, certType, password string) error
	Clear(nodeID, certType string) error
	CreateKey(nodeID, certType, subject, password string) (csr []byte, err error)
	ApplyCertificate(nodeID, certType string, cert []byte) (certURL string, err error)
	EncryptDisk(nodeID, password string) error
	FinishProvisioning(nodeID string) error
}

// CertHandler interface.
type CertHandler interface {
	GetCertTypes() []string
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
	SetOwner(certType, password string) error
	Clear(certType string) error
	CreateKey(certType, subject, password string) (csr []byte, err error)
	ApplyCertificate(certType string, cert []byte) (certURL string, err error)
	CreateSelfSignedCert(certType, password string) (err error)
}

// IdentHandler interface.
type IdentHandler interface {
	GetSystemID() (systemdID string, err error)
	GetBoardModel() (boardModel string, err error)
	GetSubjects() (Subjects []string, err error)
	SubjectsChangedChannel() (channel <-chan []string)
}

// PermissionHandler interface.
type PermissionHandler interface {
	RegisterInstance(
		instance cloudprotocol.InstanceIdent, permissions map[string]map[string]string) (secret string, err error)
	UnregisterInstance(instance cloudprotocol.InstanceIdent)
	GetPermissions(secret, funcServerID string) (
		instance cloudprotocol.InstanceIdent, permissions map[string]string, err error)
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM server instance.
func New(
	cfg *config.Config, cryptoContext *cryptutils.CryptoContext, certHandler CertHandler, identHandler IdentHandler,
	permissionHandler PermissionHandler, remoteIAMsHandler RemoteIAMsHandler, provisioningMode bool,
) (server *Server, err error) {
	server = &Server{
		cryptoContext:             cryptoContext,
		identHandler:              identHandler,
		certHandler:               certHandler,
		permissionHandler:         permissionHandler,
		remoteIAMsHandler:         remoteIAMsHandler,
		nodeID:                    cfg.NodeID,
		finishProvisioningCmdArgs: cfg.FinishProvisioningCmdArgs,
		diskEncryptCmdArgs:        cfg.DiskEncryptionCmdArgs,
	}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	var publicOpts, protectedOpts []grpc.ServerOption

	if !provisioningMode {
		tlsConfig, mtlsConfig, err := server.getTLSConfigs(cfg.CertStorage)
		if err != nil {
			return server, err
		}

		publicOpts = append(publicOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		protectedOpts = append(protectedOpts, grpc.Creds(credentials.NewTLS(mtlsConfig)))
	}

	if err = server.createPublicServer(cfg.PublicServerURL, publicOpts...); err != nil {
		return server, err
	}

	if err = server.createProtectedServer(cfg.ProtectedServerURL, provisioningMode, protectedOpts...); err != nil {
		return server, err
	}

	ctx, cancelFunction := context.WithCancel(context.Background())

	server.cancelFunction = cancelFunction

	if identHandler != nil {
		go server.handleSubjectsChanged(ctx)
	}

	return server, nil
}

// Close closes IAM server instance.
func (server *Server) Close() (err error) {
	if errCloseServerProtected := server.closeProtectedServer(); errCloseServerProtected != nil {
		if err == nil {
			err = aoserrors.Wrap(errCloseServerProtected)
		}
	}

	if errCloseServerPublic := server.closePublicServer(); errCloseServerPublic != nil {
		if err == nil {
			err = aoserrors.Wrap(errCloseServerPublic)
		}
	}

	if server.cancelFunction != nil {
		server.cancelFunction()
	}

	return err
}

// GetAPIVersion returns current iam api version.
func (server *Server) GetAPIVersion(ctx context.Context, req *empty.Empty) (*pb.APIVersion, error) {
	log.Debug("Process get API version")

	return &pb.APIVersion{Version: iamAPIVersion}, nil
}

// GetNodeID returns current iam api version.
func (server *Server) GetNodeID(ctx context.Context, req *empty.Empty) (*pb.NodeID, error) {
	log.Debug("Process get node ID")

	return &pb.NodeID{NodeId: server.nodeID}, nil
}

// CreateKey creates private key.
func (server *Server) CreateKey(context context.Context, req *pb.CreateKeyRequest) (
	rsp *pb.CreateKeyResponse, err error,
) {
	log.WithFields(log.Fields{
		"type": req.Type, "nodeID": req.NodeId, "subject": req.Subject,
	}).Debug("Process create key request")

	var (
		csr     []byte
		subject = req.Subject
	)

	rsp = &pb.CreateKeyResponse{NodeId: req.NodeId, Type: req.Type}

	defer func() {
		if err != nil {
			log.Errorf("Create key error: %v", err)
		}
	}()

	if subject == "" && server.identHandler == nil {
		return rsp, aoserrors.New("subject can't be empty")
	}

	if subject == "" && server.identHandler != nil {
		if subject, err = server.identHandler.GetSystemID(); err != nil {
			return rsp, aoserrors.Wrap(err)
		}
	}

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		csr, err = server.certHandler.CreateKey(req.Type, subject, req.Password)

	case server.remoteIAMsHandler != nil:
		csr, err = server.remoteIAMsHandler.CreateKey(req.NodeId, req.Type, subject, req.Password)

	default:
		err = aoserrors.New("unknown node ID")
	}

	rsp.Csr = string(csr)

	return rsp, err
}

// ApplyCert applies certificate.
func (server *Server) ApplyCert(
	context context.Context, req *pb.ApplyCertRequest,
) (rsp *pb.ApplyCertResponse, err error) {
	log.WithFields(log.Fields{"type": req.Type, "nodeID": req.NodeId}).Debug("Process apply cert request")

	var certURL string

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		certURL, err = server.certHandler.ApplyCertificate(req.Type, []byte(req.Cert))

	case server.remoteIAMsHandler != nil:
		certURL, err = server.remoteIAMsHandler.ApplyCertificate(req.NodeId, req.Type, []byte(req.Cert))

	default:
		err = aoserrors.New("unknown node ID")
	}

	if err != nil {
		log.Errorf("Apply certificate error: %v", err)
	}

	return &pb.ApplyCertResponse{NodeId: req.NodeId, Type: req.Type, CertUrl: certURL}, nil
}

// GetCert returns certificate URI by issuer.
func (server *Server) GetCert(context context.Context, req *pb.GetCertRequest) (rsp *pb.GetCertResponse, err error) {
	rsp = &pb.GetCertResponse{Type: req.Type}

	log.WithFields(log.Fields{
		"type":   req.Type,
		"serial": req.Serial,
		"issuer": base64.StdEncoding.EncodeToString(req.Issuer),
	}).Debug("Process get cert request")

	if rsp.CertUrl, rsp.KeyUrl, err = server.certHandler.GetCertificate(req.Type, req.Issuer, req.Serial); err != nil {
		log.Errorf("Get certificate error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// GetSystemInfo returns system information.
func (server *Server) GetSystemInfo(context context.Context, req *empty.Empty) (rsp *pb.SystemInfo, err error) {
	rsp = &pb.SystemInfo{}

	log.Debug("Process get system ID")

	if rsp.SystemId, err = server.identHandler.GetSystemID(); err != nil {
		log.Errorf("Get system ID error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	if rsp.BoardModel, err = server.identHandler.GetBoardModel(); err != nil {
		log.Errorf("Get board model error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// GetSubjects returns subjects.
func (server *Server) GetSubjects(context context.Context, req *empty.Empty) (rsp *pb.Subjects, err error) {
	rsp = &pb.Subjects{}

	log.Debug("Process get subjects")

	if rsp.Subjects, err = server.identHandler.GetSubjects(); err != nil {
		log.Errorf("Get subjects error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// SubscribeSubjectsChanged creates stream for subjects changed notifications.
func (server *Server) SubscribeSubjectsChanged(message *empty.Empty,
	stream pb.IAMPublicIdentityService_SubscribeSubjectsChangedServer,
) (err error) {
	server.Lock()
	server.subjectsChangedStreams = append(server.subjectsChangedStreams, stream)
	server.Unlock()

	log.Debug("Process subjects changed")

	<-stream.Context().Done()

	if err = stream.Context().Err(); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("Stream error: %s", err)
	} else {
		log.Debug("Stream closed")
	}

	server.Lock()
	defer server.Unlock()

	for i, item := range server.subjectsChangedStreams {
		if stream == item {
			server.subjectsChangedStreams[i] = server.subjectsChangedStreams[len(server.subjectsChangedStreams)-1]
			server.subjectsChangedStreams = server.subjectsChangedStreams[:len(server.subjectsChangedStreams)-1]

			break
		}
	}

	return nil
}

// RegisterInstance registers new service and creates secret.
func (server *Server) RegisterInstance(
	ctx context.Context, req *pb.RegisterInstanceRequest,
) (*pb.RegisterInstanceResponse, error) {
	rsp := &pb.RegisterInstanceResponse{}

	log.WithFields(log.Fields{
		"serviceID": req.Instance.ServiceId,
		"subjectID": req.Instance.SubjectId,
		"instance":  req.Instance.Instance,
	}).Debug("Process register instance")

	permissions := make(map[string]map[string]string)
	for key, value := range req.Permissions {
		permissions[key] = value.Permissions
	}

	secret, err := server.permissionHandler.RegisterInstance(instanceIdentPBToCloudprotocol(req.Instance), permissions)
	if err != nil {
		log.Errorf("Register instance error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	rsp.Secret = secret

	return rsp, nil
}

// UnregisterInstance unregisters service.
func (server *Server) UnregisterInstance(ctx context.Context, req *pb.UnregisterInstanceRequest) (*empty.Empty, error) {
	log.WithFields(log.Fields{
		"serviceID": req.Instance.ServiceId,
		"subjectID": req.Instance.SubjectId,
		"instance":  req.Instance.Instance,
	}).Debug("Process unregister instance")

	server.permissionHandler.UnregisterInstance(instanceIdentPBToCloudprotocol(req.Instance))

	return &empty.Empty{}, nil
}

// GetPermissions returns permissions by secret and functional server ID.
func (server *Server) GetPermissions(
	ctx context.Context, req *pb.PermissionsRequest,
) (rsp *pb.PermissionsResponse, err error) {
	rsp = &pb.PermissionsResponse{}

	log.WithField("funcServerID", req.FunctionalServerId).Debug("Process get permissions")

	instance, perm, err := server.permissionHandler.GetPermissions(req.Secret, req.FunctionalServerId)
	if err != nil {
		log.Errorf("Ger permissions error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	rsp.Instance = &pb.InstanceIdent{
		ServiceId: instance.ServiceID, SubjectId: instance.SubjectID,
		Instance: instance.Instance,
	}
	rsp.Permissions = &pb.Permissions{Permissions: perm}

	return rsp, nil
}

// GetAllNodeIDs returns all known node IDs.
func (server *Server) GetAllNodeIDs(context context.Context,
	req *empty.Empty,
) (rsp *pb.NodesID, err error) {
	rsp = &pb.NodesID{}

	log.Debug("Process get all node IDs")

	rsp.Ids = append(rsp.Ids, server.nodeID)

	if server.remoteIAMsHandler == nil {
		return rsp, nil
	}

remoteIAMsLoop:
	for _, remoteID := range server.remoteIAMsHandler.GetRemoteNodes() {
		for _, id := range rsp.Ids {
			if remoteID == id {
				continue remoteIAMsLoop
			}
		}

		rsp.Ids = append(rsp.Ids, remoteID)
	}

	return rsp, nil
}

// GetCertTypes returns all IAM cert types.
func (server *Server) GetCertTypes(context context.Context,
	req *pb.GetCertTypesRequest,
) (rsp *pb.CertTypes, err error) {
	log.WithField("nodeID", req.NodeId).Debug("Process get cert types")

	var certTypes []string

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		certTypes = server.certHandler.GetCertTypes()

	case server.remoteIAMsHandler != nil:
		certTypes, err = server.remoteIAMsHandler.GetCertTypes(req.NodeId)

	default:
		err = aoserrors.New("unknown node ID")
	}

	if err != nil {
		log.Errorf("Get certificate types error: %v", err)
	}

	return &pb.CertTypes{Types: certTypes}, err
}

// SetOwner makes IAM owner of secure storage.
func (server *Server) SetOwner(context context.Context, req *pb.SetOwnerRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"type": req.Type, "nodeID": req.NodeId}).Debug("Process set owner request")

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		err = server.certHandler.SetOwner(req.Type, req.Password)

	case server.remoteIAMsHandler != nil:
		err = server.remoteIAMsHandler.SetOwner(req.NodeId, req.Type, req.Password)

	default:
		err = aoserrors.New("unknown node ID")
	}

	if err != nil {
		log.Errorf("Set owner error: %v", err)
	}

	return &empty.Empty{}, err
}

// Clear clears certificates and keys storages.
func (server *Server) Clear(context context.Context, req *pb.ClearRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"type": req.Type, "nodeID": req.NodeId}).Debug("Process clear request")

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		err = server.certHandler.Clear(req.Type)

	case server.remoteIAMsHandler != nil:
		err = server.remoteIAMsHandler.Clear(req.NodeId, req.Type)

	default:
		err = aoserrors.New("unknown node ID")
	}

	if err != nil {
		log.Errorf("Clear error: %v", err)
	}

	return &empty.Empty{}, err
}

// EncryptDisk perform disk encryption.
func (server *Server) EncryptDisk(ctx context.Context, req *pb.EncryptDiskRequest) (rsp *empty.Empty, err error) {
	log.WithFields(log.Fields{"nodeID": req.NodeId}).Debug("Process encrypt disk request")

	switch {
	case req.NodeId == server.nodeID || req.NodeId == "":
		if err = server.certHandler.CreateSelfSignedCert(discEncryptionType, req.Password); err != nil {
			break
		}

		if len(server.diskEncryptCmdArgs) == 0 {
			break
		}

		output, cmdErr := exec.Command(server.diskEncryptCmdArgs[0], server.diskEncryptCmdArgs[1:]...).CombinedOutput()
		if cmdErr != nil {
			err = aoserrors.Errorf("message: %s, err: %s", string(output), err)
		}

	case server.remoteIAMsHandler != nil:
		err = server.remoteIAMsHandler.EncryptDisk(req.NodeId, req.Password)

	default:
		err = aoserrors.New("unknown node ID")
	}

	if err != nil {
		log.Errorf("Encrypt disk error: %v", err)
	}

	return &empty.Empty{}, err
}

// FinishProvisioning notifies IAM that provisioning is finished.
func (server *Server) FinishProvisioning(context context.Context, req *empty.Empty) (rsp *empty.Empty, err error) {
	log.Debug("Process finish provisioning request")

	if len(server.finishProvisioningCmdArgs) > 0 {
		output, execErr := exec.Command(
			server.finishProvisioningCmdArgs[0], server.finishProvisioningCmdArgs[1:]...).CombinedOutput()
		if execErr != nil && err == nil {
			err = aoserrors.Errorf("message: %s, err: %s", string(output), err)
		}
	}

	if server.remoteIAMsHandler != nil {
		for _, nodeID := range server.remoteIAMsHandler.GetRemoteNodes() {
			if nodeErr := server.remoteIAMsHandler.FinishProvisioning(nodeID); nodeErr != nil && err == nil {
				err = nodeErr
			}
		}
	}

	if err != nil {
		log.Errorf("Finish provisioning error: %v", err)
	}

	return &empty.Empty{}, err
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (server *Server) getTLSConfigs(certStorage string) (tlsConfig, mtlsConfig *tls.Config, err error) {
	certURL, keyURL, err := server.certHandler.GetCertificate(certStorage, nil, "")
	if err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	if tlsConfig, err = server.cryptoContext.GetServerTLSConfig(certURL, keyURL); err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	if mtlsConfig, err = server.cryptoContext.GetServerMutualTLSConfig(certURL, keyURL); err != nil {
		return nil, nil, aoserrors.Wrap(err)
	}

	return tlsConfig, mtlsConfig, nil
}

func (server *Server) createPublicServer(url string, opts ...grpc.ServerOption) (err error) {
	log.WithField("url", url).Debug("Create IAM public server")

	if server.publicListener, err = net.Listen("tcp", url); err != nil {
		return aoserrors.Wrap(err)
	}

	server.grpcPublicServer = grpc.NewServer(opts...)

	server.registerPublicServices(server.grpcPublicServer)

	go func() {
		if err := server.grpcPublicServer.Serve(server.publicListener); err != nil {
			log.Errorf("Can't serve public grpc server: %s", err)
		}
	}()

	return nil
}

func (server *Server) createProtectedServer(url string, provisioningMode bool, opts ...grpc.ServerOption) (err error) {
	log.WithField("url", url).Debug("Create IAM protected server")

	if server.protectedListener, err = net.Listen("tcp", url); err != nil {
		return aoserrors.Wrap(err)
	}

	server.grpcProtectedServer = grpc.NewServer(opts...)

	server.registerPublicServices(server.grpcProtectedServer)
	server.registerProtectedServices(server.grpcProtectedServer, provisioningMode)

	go func() {
		if err := server.grpcProtectedServer.Serve(server.protectedListener); err != nil {
			log.Errorf("Can't serve grpc server: %s", err)
		}
	}()

	return nil
}

func (server *Server) closePublicServer() (err error) {
	log.Debug("Close IAM public server")

	if server.grpcPublicServer != nil {
		server.grpcPublicServer.Stop()
	}

	if server.publicListener != nil {
		if listenerErr := server.publicListener.Close(); listenerErr != nil {
			if err == nil {
				err = listenerErr
			}
		}
	}

	return aoserrors.Wrap(err)
}

func (server *Server) closeProtectedServer() (err error) {
	log.Debug("Close IAM protected server")

	if server.grpcProtectedServer != nil {
		server.grpcProtectedServer.Stop()
	}

	if server.protectedListener != nil {
		if listenerErr := server.protectedListener.Close(); listenerErr != nil {
			if err == nil {
				err = listenerErr
			}
		}
	}

	return aoserrors.Wrap(err)
}

func (server *Server) handleSubjectsChanged(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case subjects := <-server.identHandler.SubjectsChangedChannel():
			server.Lock()

			log.WithField("subjects", subjects).Debug("Handle subjects changed")

			for _, stream := range server.subjectsChangedStreams {
				if err := stream.Send(&pb.Subjects{Subjects: subjects}); err != nil {
					log.Errorf("Can't send subjects: %s", err)
				}
			}

			server.Unlock()
		}
	}
}

func instanceIdentPBToCloudprotocol(ident *pb.InstanceIdent) cloudprotocol.InstanceIdent {
	return cloudprotocol.InstanceIdent{
		ServiceID: ident.ServiceId, SubjectID: ident.SubjectId, Instance: ident.Instance,
	}
}

func (server *Server) registerPublicServices(registrar grpc.ServiceRegistrar) {
	pb.RegisterIAMPublicServiceServer(registrar, server)

	if server.identHandler != nil {
		pb.RegisterIAMPublicIdentityServiceServer(registrar, server)
	}

	if server.permissionHandler != nil {
		pb.RegisterIAMPublicPermissionsServiceServer(registrar, server)
	}
}

func (server *Server) registerProtectedServices(registrar grpc.ServiceRegistrar, provisioningMode bool) {
	pb.RegisterIAMCertificateServiceServer(registrar, server)

	if provisioningMode {
		pb.RegisterIAMProvisioningServiceServer(registrar, server)
	}

	if server.permissionHandler != nil {
		pb.RegisterIAMPermissionsServiceServer(registrar, server)
	}
}
