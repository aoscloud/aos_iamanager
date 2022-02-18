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
	"encoding/base64"
	"errors"
	"net"
	"os/exec"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v1"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/aoscloud/aos_iamanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const discEncryptyonType = "diskencryption"

/*******************************************************************************
 * Vars
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

// Server IAM server instance.
type Server struct {
	sync.Mutex

	identHandler              IdentHandler
	certHandler               CertHandler
	permissionHandler         PermissionHandler
	listener                  net.Listener
	listenerPublic            net.Listener
	grpcServer                *grpc.Server
	grpcServerPublic          *grpc.Server
	usersChangedStreams       []pb.IAMPublicService_SubscribeUsersChangedServer
	closeChannel              chan struct{}
	streamsWg                 sync.WaitGroup
	finishProvisioningCmdArgs []string
	diskEncryptCmdArgs        []string
	pb.UnimplementedIAMProtectedServiceServer
	pb.UnimplementedIAMPublicServiceServer
}

// CertHandler interface.
type CertHandler interface {
	GetCertTypes() (certTypes []string)
	SetOwner(certType, password string) (err error)
	Clear(certType string) (err error)
	CreateKey(certType, password string) (csr []byte, err error)
	ApplyCertificate(certType string, cert []byte) (certURL string, err error)
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
	CreateSelfSignedCert(certType, password string) (err error)
}

// IdentHandler interface.
type IdentHandler interface {
	GetSystemID() (systemdID string, err error)
	GetBoardModel() (boardModel string, err error)
	GetUsers() (users []string, err error)
	SetUsers(users []string) (err error)
	UsersChangedChannel() (channel <-chan []string)
}

// PermissionHandler interface.
type PermissionHandler interface {
	RegisterService(serviceID string, funcServerPermissions map[string]map[string]string) (secret string, err error)
	UnregisterService(serviceID string)
	GetPermissions(secret, funcServerID string) (serviceID string, permissions map[string]string, err error)
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new IAM server instance.
func New(cfg *config.Config, identHandler IdentHandler, certHandler CertHandler,
	permissionHandler PermissionHandler, insecure bool) (server *Server, err error) {
	server = &Server{
		identHandler:              identHandler,
		certHandler:               certHandler,
		permissionHandler:         permissionHandler,
		closeChannel:              make(chan struct{}, 1),
		finishProvisioningCmdArgs: cfg.FinishProvisioningCmdArgs,
		diskEncryptCmdArgs:        cfg.DiskEncryptionCmdArgs,
	}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	if err := server.createServerProtected(cfg, insecure); err != nil {
		return server, aoserrors.Wrap(err)
	}

	if err := server.createServerPublic(cfg, insecure); err != nil {
		return server, aoserrors.Wrap(err)
	}

	go server.handleUsersChanged()

	return server, nil
}

// Close closes IAM server instance.
func (server *Server) Close() (err error) {
	if errCloseServerProtected := server.closeServerProtected(); errCloseServerProtected != nil {
		if err == nil {
			err = errCloseServerProtected
		}
	}

	if errCloseServerPublic := server.closeServerPublic(); errCloseServerPublic != nil {
		if err == nil {
			err = errCloseServerPublic
		}
	}

	return aoserrors.Wrap(err)
}

// GetCertTypes return all IAM cert types.
func (server *Server) GetCertTypes(context context.Context, req *empty.Empty) (rsp *pb.CertTypes, err error) {
	rsp = &pb.CertTypes{Types: server.certHandler.GetCertTypes()}

	log.WithField("types", rsp.Types).Debug("Process get cert types")

	return rsp, nil
}

// FinishProvisioning notifies IAM that provisioning is finished.
func (server *Server) FinishProvisioning(context context.Context, req *empty.Empty) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	if len(server.finishProvisioningCmdArgs) > 0 {
		output, err := exec.Command(
			server.finishProvisioningCmdArgs[0], server.finishProvisioningCmdArgs[1:]...).CombinedOutput()
		if err != nil {
			return rsp, aoserrors.Errorf("message: %s, err: %s", string(output), err)
		}
	}

	return rsp, nil
}

// SetOwner makes IAM owner of secure storage.
func (server *Server) SetOwner(context context.Context, req *pb.SetOwnerRequest) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("type", req.Type).Debug("Process set owner request")

	if err = server.certHandler.SetOwner(req.Type, req.Password); err != nil {
		log.Errorf("Set owner error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// Clear clears certificates and keys storages.
func (server *Server) Clear(context context.Context, req *pb.ClearRequest) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("type", req.Type).Debug("Process clear request")

	if err = server.certHandler.Clear(req.Type); err != nil {
		log.Errorf("Clear error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// CreateKey creates private key.
func (server *Server) CreateKey(context context.Context, req *pb.CreateKeyRequest) (
	rsp *pb.CreateKeyResponse, err error) {
	rsp = &pb.CreateKeyResponse{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process create key request")

	csr, err := server.certHandler.CreateKey(req.Type, req.Password)
	if err != nil {
		log.Errorf("Create key error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	rsp.Csr = string(csr)

	return rsp, nil
}

// ApplyCert applies certificate.
func (server *Server) ApplyCert(
	context context.Context, req *pb.ApplyCertRequest) (rsp *pb.ApplyCertResponse, err error) {
	rsp = &pb.ApplyCertResponse{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process apply cert request")

	if rsp.CertUrl, err = server.certHandler.ApplyCertificate(req.Type, []byte(req.Cert)); err != nil {
		log.Errorf("Apply certificate error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
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

// GetUsers returns users.
func (server *Server) GetUsers(context context.Context, req *empty.Empty) (rsp *pb.Users, err error) {
	rsp = &pb.Users{}

	log.Debug("Process get users")

	if rsp.Users, err = server.identHandler.GetUsers(); err != nil {
		log.Errorf("Get users error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// SetUsers sets users.
func (server *Server) SetUsers(context context.Context, req *pb.Users) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("users", req.Users).Debug("Process set users")

	if err = server.identHandler.SetUsers(req.Users); err != nil {
		log.Errorf("Set users error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}

// SubscribeUsersChanged creates stream for users changed notifications.
func (server *Server) SubscribeUsersChanged(message *empty.Empty,
	stream pb.IAMPublicService_SubscribeUsersChangedServer) (err error) {
	server.streamsWg.Add(1)

	server.Lock()
	server.usersChangedStreams = append(server.usersChangedStreams, stream)
	server.Unlock()

	log.Debug("Process users changed")

	<-stream.Context().Done()

	if err = stream.Context().Err(); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("Stream error: %s", err)
	} else {
		log.Debug("Stream closed")
	}

	server.Lock()
	defer server.Unlock()

	for i, item := range server.usersChangedStreams {
		if stream == item {
			server.usersChangedStreams[i] = server.usersChangedStreams[len(server.usersChangedStreams)-1]
			server.usersChangedStreams = server.usersChangedStreams[:len(server.usersChangedStreams)-1]

			break
		}
	}

	server.streamsWg.Done()

	return nil
}

// RegisterService registers new service and creates secret.
func (server *Server) RegisterService(
	ctx context.Context, req *pb.RegisterServiceRequest) (rsp *pb.RegisterServiceResponse, err error) {
	rsp = &pb.RegisterServiceResponse{}

	log.WithField("serviceID", req.ServiceId).Debug("Process register service")

	permissions := make(map[string]map[string]string)
	for key, value := range req.Permissions {
		permissions[key] = value.Permissions
	}

	secret, err := server.permissionHandler.RegisterService(req.ServiceId, permissions)
	if err != nil {
		log.Errorf("Register service error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	rsp.Secret = secret

	return rsp, nil
}

// UnregisterService unregisters service.
func (server *Server) UnregisterService(
	ctx context.Context, req *pb.UnregisterServiceRequest) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("serviceID", req.ServiceId).Debug("Process unregister service")

	server.permissionHandler.UnregisterService(req.ServiceId)

	return rsp, nil
}

// GetPermissions returns permissions by secret and functional server ID.
func (server *Server) GetPermissions(
	ctx context.Context, req *pb.PermissionsRequest) (rsp *pb.PermissionsResponse, err error) {
	rsp = &pb.PermissionsResponse{}

	log.WithField("funcServerID", req.FunctionalServerId).Debug("Process get permissions")

	serviceID, perm, err := server.permissionHandler.GetPermissions(req.Secret, req.FunctionalServerId)
	if err != nil {
		log.Errorf("Ger permissions error: %s", err)

		return rsp, aoserrors.Wrap(err)
	}

	rsp.ServiceId = serviceID
	rsp.Permissions = &pb.Permissions{Permissions: perm}

	return rsp, nil
}

// EncryptDisk perform disk encryption.
func (server *Server) EncryptDisk(ctx context.Context, req *pb.EncryptDiskRequest) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	if err := server.certHandler.CreateSelfSignedCert(discEncryptyonType, req.Password); err != nil {
		log.Error("Can't generate self signed certificate: ", err)
		return rsp, aoserrors.Wrap(err)
	}

	if len(server.diskEncryptCmdArgs) > 0 {
		output, err := exec.Command(server.diskEncryptCmdArgs[0], server.diskEncryptCmdArgs[1:]...).CombinedOutput()
		if err != nil {
			return rsp, aoserrors.Errorf("Can't encrypt disk: %s, err: %s", string(output), err)
		}
	}

	return rsp, nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (server *Server) createServerProtected(cfg *config.Config, insecure bool) (err error) {
	log.WithField("url", cfg.ServerURL).Debug("Create IAM protected server")

	if server.listener, err = net.Listen("tcp", cfg.ServerURL); err != nil {
		return aoserrors.Wrap(err)
	}

	var opts []grpc.ServerOption

	if !insecure {
		tlsConfig, err := cryptutils.GetServerMutualTLSConfig(cfg.CACert, cfg.CertStorage)
		if err != nil {
			log.Errorf("Can't get mTLS config: %s", err)
		} else {
			opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}
	} else {
		log.Warnf("IAM server uses insecure connection")
	}

	server.grpcServer = grpc.NewServer(opts...)

	pb.RegisterIAMProtectedServiceServer(server.grpcServer, server)
	pb.RegisterIAMPublicServiceServer(server.grpcServer, server)

	go func() {
		if err := server.grpcServer.Serve(server.listener); err != nil {
			log.Errorf("Can't serve grpc server: %s", err)
		}
	}()

	return nil
}

func (server *Server) createServerPublic(cfg *config.Config, insecure bool) (err error) {
	log.WithField("url", cfg.ServerPublicURL).Debug("Create IAM public server")

	if server.listenerPublic, err = net.Listen("tcp", cfg.ServerPublicURL); err != nil {
		return aoserrors.Wrap(err)
	}

	var opts []grpc.ServerOption

	if !insecure {
		tlsConfig, err := cryptutils.GetServerTLSConfig(cfg.CertStorage)
		if err != nil {
			log.Errorf("Can't get TLS config: %s", err)
		} else {
			opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}
	} else {
		log.Warnf("IAM public server uses insecure connection")
	}

	server.grpcServerPublic = grpc.NewServer(opts...)

	pb.RegisterIAMPublicServiceServer(server.grpcServerPublic, server)

	go func() {
		if err := server.grpcServerPublic.Serve(server.listenerPublic); err != nil {
			log.Errorf("Can't serve public grpc server: %s", err)
		}
	}()

	return nil
}

func (server *Server) closeServerProtected() (err error) {
	log.Debug("Close IAM protected server")

	if server.grpcServer != nil {
		server.grpcServer.Stop()
	}

	if server.listener != nil {
		if listenerErr := server.listener.Close(); listenerErr != nil {
			if err == nil {
				err = listenerErr
			}
		}
	}

	server.closeChannel <- struct{}{}

	server.streamsWg.Wait()

	return aoserrors.Wrap(err)
}

func (server *Server) closeServerPublic() (err error) {
	log.Debug("Close IAM public server")

	if server.grpcServerPublic != nil {
		server.grpcServerPublic.Stop()
	}

	if server.listenerPublic != nil {
		if listenerErr := server.listenerPublic.Close(); listenerErr != nil {
			if err == nil {
				err = listenerErr
			}
		}
	}

	return aoserrors.Wrap(err)
}

func (server *Server) handleUsersChanged() {
	for {
		select {
		case <-server.closeChannel:
			return

		case users := <-server.identHandler.UsersChangedChannel():
			server.Lock()

			log.WithField("users", users).Debug("Handle users changed")

			for _, stream := range server.usersChangedStreams {
				if err := stream.Send(&pb.Users{Users: users}); err != nil {
					log.Errorf("Can't send users: %s", err)
				}
			}

			server.Unlock()
		}
	}
}
