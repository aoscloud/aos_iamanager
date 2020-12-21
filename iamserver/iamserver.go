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
	"net"
	"sync"

	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	pb "gitpct.epam.com/epmd-aepr/aos_common/api/iamanager"
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

	identHandler        IdentHandler
	certHandler         CertHandler
	listener            net.Listener
	grpcServer          *grpc.Server
	usersChangedStreams []pb.IAManager_SubscribeUsersChangedServer
	closeChannel        chan struct{}
	streamsWg           sync.WaitGroup
}

// CertHandler interface
type CertHandler interface {
	SetOwner(certType, password string) (err error)
	Clear(certType string) (err error)
	CreateKeys(certType, password string) (csr string, err error)
	ApplyCertificate(certType string, cert string) (certURL string, err error)
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
}

// IdentHandler interface
type IdentHandler interface {
	GetSystemID() (systemdID string, err error)
	GetUsers() (users []string, err error)
	SetUsers(users []string) (err error)
	UsersChangedChannel() (channel <-chan []string)
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new IAM server instance
func New(cfg *config.Config, identHandler IdentHandler, certHandler CertHandler, insecure bool) (server *Server, err error) {
	log.WithField("url", cfg.ServerURL).Debug("Create IAM server")

	server = &Server{identHandler: identHandler, certHandler: certHandler, closeChannel: make(chan struct{}, 1)}

	defer func() {
		if err != nil {
			server.Close()
		}
	}()

	if server.listener, err = net.Listen("tcp", cfg.ServerURL); err != nil {
		return server, err
	}

	if insecure == false {
		creds, err := credentials.NewServerTLSFromFile(cfg.Cert, cfg.Key)
		if err != nil {
			return server, err
		}

		server.grpcServer = grpc.NewServer(grpc.Creds(creds))
	} else {
		log.Warnf("IAM server uses insecure connection")

		server.grpcServer = grpc.NewServer()
	}

	pb.RegisterIAManagerServer(server.grpcServer, server)

	go server.grpcServer.Serve(server.listener)

	go server.handleUsersChanged()

	return server, nil
}

// Close closes IAM server instance
func (server *Server) Close() (err error) {
	log.Debug("Close IAM server")

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

// CreateKeys creates private keys
func (server *Server) CreateKeys(context context.Context, req *pb.CreateKeysReq) (rsp *pb.CreateKeysRsp, err error) {
	rsp = &pb.CreateKeysRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process create keys request")

	if rsp.Csr, err = server.certHandler.CreateKeys(req.Type, req.Password); err != nil {
		return rsp, err
	}

	return rsp, nil
}

// ApplyCert applies certificate
func (server *Server) ApplyCert(context context.Context, req *pb.ApplyCertReq) (rsp *pb.ApplyCertRsp, err error) {
	rsp = &pb.ApplyCertRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process apply cert request")

	if rsp.CertUrl, err = server.certHandler.ApplyCertificate(req.Type, req.Cert); err != nil {
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

// GetSystemID returns system ID
func (server *Server) GetSystemID(context context.Context, req *empty.Empty) (rsp *pb.GetSystemIDRsp, err error) {
	rsp = &pb.GetSystemIDRsp{}

	log.Debug("Process get system ID")

	if rsp.Id, err = server.identHandler.GetSystemID(); err != nil {
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

/*******************************************************************************
 * Private
 ******************************************************************************/

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
