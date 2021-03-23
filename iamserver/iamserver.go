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

package iamserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	pb "gitpct.epam.com/epmd-aepr/aos_common/api/iamanager"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"aos_iamanager/config"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

/*******************************************************************************
 * Vars
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

// Server IAM server instance
type Server struct {
	sync.Mutex

	identHandler              IdentHandler
	certHandler               CertHandler
	permissionHandler         PermissionHandler
	listener                  net.Listener
	listenerPublic            net.Listener
	grpcServer                *grpc.Server
	grpcServerPublic          *grpc.Server
	usersChangedStreams       []pb.IAManager_SubscribeUsersChangedServer
	closeChannel              chan struct{}
	streamsWg                 sync.WaitGroup
	finishProvisioningCmdArgs []string
}

// CertHandler interface
type CertHandler interface {
	GetCertTypes() (certTypes []string)
	SetOwner(certType, password string) (err error)
	Clear(certType string) (err error)
	CreateKey(certType, password string) (csr []byte, err error)
	ApplyCertificate(certType string, cert []byte) (certURL string, err error)
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
}

// IdentHandler interface
type IdentHandler interface {
	GetSystemID() (systemdID string, err error)
	GetBoardModel() (boardModel string, err error)
	GetUsers() (users []string, err error)
	SetUsers(users []string) (err error)
	UsersChangedChannel() (channel <-chan []string)
}

// PermissionHandler interface
type PermissionHandler interface {
	RegisterService(serviceID string, funcServerPermissions map[string]map[string]string) (secret string, err error)
	UnregisterService(serviceID string)
	GetPermissions(secret, funcServerId string) (permissions map[string]string, err error)
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new IAM server instance
func New(cfg *config.Config, identHandler IdentHandler, certHandler CertHandler, permissionHandler PermissionHandler, insecure bool) (server *Server, err error) {
	server = &Server{
		identHandler:              identHandler,
		certHandler:               certHandler,
		permissionHandler:         permissionHandler,
		closeChannel:              make(chan struct{}, 1),
		finishProvisioningCmdArgs: cfg.FinishProvisioningCmdArgs}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	if err := server.createServerProtected(cfg, insecure); err != nil {
		return server, err
	}

	if err := server.createServerPublic(cfg, insecure); err != nil {
		return server, err
	}

	go server.handleUsersChanged()

	return server, nil
}

// Close closes IAM server instance
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

	return err
}

// GetCertTypes return all IAM cert types
func (server *Server) GetCertTypes(context context.Context, req *empty.Empty) (rsp *pb.GetCertTypesRsp, err error) {
	rsp = &pb.GetCertTypesRsp{Types: server.certHandler.GetCertTypes()}

	log.WithField("types", rsp.Types).Debug("Process get cert types")

	return rsp, nil
}

// FinishProvisioning notifies IAM that provisioning is finished
func (server *Server) FinishProvisioning(context context.Context, req *empty.Empty) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	if len(server.finishProvisioningCmdArgs) > 0 {
		output, err := exec.Command(server.finishProvisioningCmdArgs[0], server.finishProvisioningCmdArgs[1:]...).CombinedOutput()
		if err != nil {
			return rsp, fmt.Errorf("message: %s, err: %s", string(output), err)
		}
	}

	return rsp, nil
}

// SetOwner makes IAM owner of secure storage
func (server *Server) SetOwner(context context.Context, req *pb.SetOwnerReq) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("type", req.Type).Debug("Process set owner request")

	if err = server.certHandler.SetOwner(req.Type, req.Password); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// Clear clears certificates and keys storages
func (server *Server) Clear(context context.Context, req *pb.ClearReq) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("type", req.Type).Debug("Process clear request")

	if err = server.certHandler.Clear(req.Type); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// CreateKey creates private key
func (server *Server) CreateKey(context context.Context, req *pb.CreateKeyReq) (rsp *pb.CreateKeyRsp, err error) {
	rsp = &pb.CreateKeyRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process create key request")

	csr, err := server.certHandler.CreateKey(req.Type, req.Password)
	if err != nil {
		return rsp, err
	}

	rsp.Csr = string(csr)

	return rsp, nil
}

// ApplyCert applies certificate
func (server *Server) ApplyCert(context context.Context, req *pb.ApplyCertReq) (rsp *pb.ApplyCertRsp, err error) {
	rsp = &pb.ApplyCertRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process apply cert request")

	if rsp.CertUrl, err = server.certHandler.ApplyCertificate(req.Type, []byte(req.Cert)); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// GetCert returns certificate URI by issuer
func (server *Server) GetCert(context context.Context, req *pb.GetCertReq) (rsp *pb.GetCertRsp, err error) {
	rsp = &pb.GetCertRsp{Type: req.Type}

	log.WithFields(log.Fields{
		"type":   req.Type,
		"serial": req.Serial,
		"issuer": base64.StdEncoding.EncodeToString(req.Issuer)}).Debug("Process get cert request")

	if rsp.CertUrl, rsp.KeyUrl, err = server.certHandler.GetCertificate(req.Type, req.Issuer, req.Serial); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// GetSystemInfo returns system information
func (server *Server) GetSystemInfo(context context.Context, req *empty.Empty) (rsp *pb.GetSystemInfoRsp, err error) {
	rsp = &pb.GetSystemInfoRsp{}

	log.Debug("Process get system ID")

	if rsp.SystemId, err = server.identHandler.GetSystemID(); err != nil {
		return rsp, err
	}

	if rsp.BoardModel, err = server.identHandler.GetBoardModel(); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// GetUsers returns users
func (server *Server) GetUsers(context context.Context, req *empty.Empty) (rsp *pb.GetUsersRsp, err error) {
	rsp = &pb.GetUsersRsp{}

	log.Debug("Process get users")

	if rsp.Users, err = server.identHandler.GetUsers(); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// SetUsers sets users
func (server *Server) SetUsers(context context.Context, req *pb.SetUsersReq) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("users", req.Users).Debug("Process set users")

	if err = server.identHandler.SetUsers(req.Users); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// SubscribeUsersChanged creates stream for users changed notifications
func (server *Server) SubscribeUsersChanged(message *empty.Empty, stream pb.IAManager_SubscribeUsersChangedServer) (err error) {
	server.streamsWg.Add(1)

	server.Lock()
	server.usersChangedStreams = append(server.usersChangedStreams, stream)
	server.Unlock()

	log.Debug("Process users changed")

	<-stream.Context().Done()

	if err = stream.Context().Err(); err != nil && err != context.Canceled {
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

// RegisterService registers new service and creates secret
func (server *Server) RegisterService(ctx context.Context, req *pb.RegisterServiceReq) (rsp *pb.RegisterServiceRsp, err error) {
	rsp = &pb.RegisterServiceRsp{}

	log.WithField("serviceID", req.ServiceId).Debug("Process register service")

	permissions := make(map[string]map[string]string)
	for key, value := range req.Permissions {
		permissions[key] = value.Permissions
	}

	secret, err := server.permissionHandler.RegisterService(req.ServiceId, permissions)
	if err != nil {
		return rsp, err
	}

	rsp.Secret = secret

	return rsp, nil
}

// UnregisterService unregisters service
func (server *Server) UnregisterService(ctx context.Context, req *pb.UnregisterServiceReq) (rsp *empty.Empty, err error) {
	rsp = &empty.Empty{}

	log.WithField("serviceID", req.ServiceId).Debug("Process unregister service")

	server.permissionHandler.UnregisterService(req.ServiceId)

	return rsp, nil
}

// GetPermissions returns permissions by secret and functional server ID
func (server *Server) GetPermissions(ctx context.Context, req *pb.GetPermissionsReq) (rsp *pb.Permissions, err error) {
	rsp = &pb.Permissions{}

	log.WithField("funcServerID", req.FunctionalServerId).Debug("Process get permissions")

	perm, err := server.permissionHandler.GetPermissions(req.Secret, req.FunctionalServerId)
	if err != nil {
		return rsp, err
	}

	rsp.Permissions = perm

	return rsp, nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (server *Server) createServerProtected(cfg *config.Config, insecure bool) (err error) {
	log.WithField("url", cfg.ServerURL).Debug("Create IAM protected server")

	if server.listener, err = net.Listen("tcp", cfg.ServerURL); err != nil {
		return err
	}

	var opts []grpc.ServerOption

	if insecure == false {
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

	pb.RegisterIAManagerServer(server.grpcServer, server)
	pb.RegisterIAManagerPublicServer(server.grpcServer, server)

	go server.grpcServer.Serve(server.listener)

	return nil
}

func (server *Server) createServerPublic(cfg *config.Config, insecure bool) (err error) {
	log.WithField("url", cfg.ServerPublicURL).Debug("Create IAM public server")

	if server.listenerPublic, err = net.Listen("tcp", cfg.ServerPublicURL); err != nil {
		return err
	}

	var opts []grpc.ServerOption

	if insecure == false {
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

	pb.RegisterIAManagerPublicServer(server.grpcServerPublic, server)

	go server.grpcServerPublic.Serve(server.listenerPublic)

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

	return err
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

	return err
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
				if err := stream.Send(&pb.UsersChangedNtf{Users: users}); err != nil {
					log.Errorf("Can't send users: %s", err)
				}
			}

			server.Unlock()
		}
	}
}
