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

package cmserver

import (
	"context"
	"encoding/base64"
	"net"

	log "github.com/sirupsen/logrus"
	pb "gitpct.epam.com/epmd-aepr/aos_common/api/certificatemanager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"aos_certificatemanager/config"
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

// Server CM server instance
type Server struct {
	certHandler CertHandler
	listener    net.Listener
	grpcServer  *grpc.Server
}

// CertHandler interface
type CertHandler interface {
	CreateKeys(certType, systemdID, password string) (csr string, err error)
	ApplyCertificate(certType string, cert string) (certURL string, err error)
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new CM server instance
func New(cfg *config.Config, certHandler CertHandler, insecure bool) (server *Server, err error) {
	log.WithField("url", cfg.ServerURL).Debug("Create CM server")

	server = &Server{certHandler: certHandler}

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
		log.Warnf("CM server uses insecure connection")

		server.grpcServer = grpc.NewServer()
	}

	pb.RegisterCertificateManagerServer(server.grpcServer, server)

	go server.grpcServer.Serve(server.listener)

	return server, nil
}

// Close closes CM server instance
func (server *Server) Close() (err error) {
	log.Debug("Close CM server")

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

	return err
}

// CreateKeys creates private keys
func (server *Server) CreateKeys(context context.Context, req *pb.CreateKeysReq) (rsp *pb.CreateKeysRsp, err error) {
	rsp = &pb.CreateKeysRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process create keys request")

	if rsp.Csr, err = server.certHandler.CreateKeys(req.Type, req.SystemId, req.Password); err != nil {
		rsp.Error = err.Error()
	}

	return rsp, nil
}

// ApplyCert applies certificate
func (server *Server) ApplyCert(context context.Context, req *pb.ApplyCertReq) (rsp *pb.ApplyCertRsp, err error) {
	rsp = &pb.ApplyCertRsp{Type: req.Type}

	log.WithField("type", req.Type).Debug("Process apply cert request")

	if rsp.CertUrl, err = server.certHandler.ApplyCertificate(req.Type, req.Cert); err != nil {
		rsp.Error = err.Error()
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
		rsp.Error = err.Error()
	}

	return rsp, nil
}
