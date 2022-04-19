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
	"github.com/aoscloud/aos_common/api/cloudprotocol"
	pb "github.com/aoscloud/aos_common/api/iamanager/v2"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/aoscloud/aos_iamanager/certhandler"
	"github.com/aoscloud/aos_iamanager/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const discEncryptyonType = "diskencryption"

const iamAPIVersion = 2

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Server IAM server instance.
type Server struct {
	sync.Mutex

	identHandler      IdentHandler
	certHandler       CertHandler
	permissionHandler PermissionHandler

	cryptoContext             *cryptutils.CryptoContext
	listener                  net.Listener
	listenerPublic            net.Listener
	grpcServer                *grpc.Server
	grpcServerPublic          *grpc.Server
	subjectsChangedStreams    []pb.IAMPublicService_SubscribeSubjectsChangedServer
	finishProvisioningCmdArgs []string
	diskEncryptCmdArgs        []string
	pb.UnimplementedIAMProtectedServiceServer
	pb.UnimplementedIAMPublicServiceServer
	cancelFunction context.CancelFunc
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
func New(cfg *config.Config, identHandler IdentHandler, certHandler CertHandler,
	permissionHandler PermissionHandler, insecure bool,
) (server *Server, err error) {
	server = &Server{
		identHandler:              identHandler,
		certHandler:               certHandler,
		permissionHandler:         permissionHandler,
		finishProvisioningCmdArgs: cfg.FinishProvisioningCmdArgs,
		diskEncryptCmdArgs:        cfg.DiskEncryptionCmdArgs,
	}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	if server.cryptoContext, err = cryptutils.NewCryptoContext(cfg.CACert); err != nil {
		return server, aoserrors.Wrap(err)
	}

	if err := server.createServerProtected(cfg, insecure); err != nil {
		return server, aoserrors.Wrap(err)
	}

	if err := server.createServerPublic(cfg, insecure); err != nil {
		return server, aoserrors.Wrap(err)
	}

	ctx, cancelFunction := context.WithCancel(context.Background())

	server.cancelFunction = cancelFunction

	go server.handleSubjectsChanged(ctx)

	return server, nil
}

// Close closes IAM server instance.
func (server *Server) Close() (err error) {
	if errCloseServerProtected := server.closeServerProtected(); errCloseServerProtected != nil {
		if err == nil {
			err = aoserrors.Wrap(errCloseServerProtected)
		}
	}

	if errCloseServerPublic := server.closeServerPublic(); errCloseServerPublic != nil {
		if err == nil {
			err = aoserrors.Wrap(errCloseServerPublic)
		}
	}

	if errCryptoContext := server.cryptoContext.Close(); errCryptoContext != nil {
		if err == nil {
			err = aoserrors.Wrap(errCryptoContext)
		}
	}

	if server.cancelFunction != nil {
		server.cancelFunction()
	}

	return err
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
	rsp *pb.CreateKeyResponse, err error,
) {
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
	context context.Context, req *pb.ApplyCertRequest,
) (rsp *pb.ApplyCertResponse, err error) {
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
	stream pb.IAMPublicService_SubscribeSubjectsChangedServer,
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
		Instance: int64(instance.Instance),
	}
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

// GetAPIVersion returns current iam api version.
func (server *Server) GetAPIVersion(ctx context.Context, req *empty.Empty) (resp *pb.APIVersion, err error) {
	return &pb.APIVersion{Version: iamAPIVersion}, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (server *Server) createServerProtected(cfg *config.Config, insecure bool) (err error) {
	log.WithField("url", cfg.ServerURL).Debug("Create IAM protected server")

	if server.listener, err = net.Listen("tcp", cfg.ServerURL); err != nil {
		return aoserrors.Wrap(err)
	}

	var opts []grpc.ServerOption

	if !insecure {
		certURL, keyURL, err := server.certHandler.GetCertificate(cfg.CertStorage, nil, "")
		if err != nil {
			if !errors.Is(err, certhandler.ErrNotExist) {
				return aoserrors.Wrap(err)
			}

			log.Errorf("Can't get TLS certificate: %s. Continue in insecure mode.", err)
		} else {
			tlsConfig, err := server.cryptoContext.GetServerMutualTLSConfig(certURL, keyURL)
			if err != nil {
				return aoserrors.Wrap(err)
			}

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
		certURL, keyURL, err := server.certHandler.GetCertificate(cfg.CertStorage, nil, "")
		if err != nil {
			if !errors.Is(err, certhandler.ErrNotExist) {
				return aoserrors.Wrap(err)
			}

			log.Errorf("Can't get public TLS certificate: %s. Continue in insecure mode.", err)
		} else {
			tlsConfig, err := server.cryptoContext.GetServerTLSConfig(certURL, keyURL)
			if err != nil {
				return aoserrors.Wrap(err)
			}

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
		ServiceID: ident.ServiceId, SubjectID: ident.SubjectId, Instance: uint64(ident.Instance),
	}
}
