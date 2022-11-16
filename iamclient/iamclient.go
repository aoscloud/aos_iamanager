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

package iamclient

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	pb "github.com/aoscloud/aos_common/api/iamanager/v4"
	"github.com/aoscloud/aos_common/utils/cryptutils"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aoscloud/aos_iamanager/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	connectionTimeout = 10 * time.Minute
	requestTimeout    = 30 * time.Second
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// CertHandler interface.
type CertHandler interface {
	GetCertificate(certType string, issuer []byte, serial string) (certURL, keyURL string, err error)
}

// Client IAM client instance.
type Client struct {
	cryptoContext    *cryptutils.CryptoContext
	certHandler      CertHandler
	provisioningMode bool
	dialOptions      []grpc.DialOption
	remoteIAMs       map[string]*remoteIAM
	ctx              context.Context // nolint: containedctx // used to keep common context
	cancelFunc       context.CancelFunc
}

type remoteIAM struct {
	sync.Mutex

	connection      *grpc.ClientConn
	connectionTimer *time.Timer
	cfg             config.RemoteIAM
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errNodeNotFound = errors.New("node not found")

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM client instance.
func New(
	cfg *config.Config, cryptoContext *cryptutils.CryptoContext, certHandler CertHandler, provisioningMode bool,
) (client *Client, err error) {
	client = &Client{
		cryptoContext:    cryptoContext,
		certHandler:      certHandler,
		provisioningMode: provisioningMode,
		remoteIAMs:       make(map[string]*remoteIAM),
	}

	defer func() {
		if err != nil {
			client.Close()
		}
	}()

	if provisioningMode {
		client.dialOptions = append(client.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig, err := client.getTLSConfig(cfg.CertStorage)
		if err != nil {
			return nil, err
		}

		client.dialOptions = append(client.dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	for _, iamCfg := range cfg.RemoteIAMs {
		client.remoteIAMs[iamCfg.NodeID] = &remoteIAM{cfg: iamCfg}
	}

	client.dialOptions = append(client.dialOptions, grpc.WithBlock())

	client.ctx, client.cancelFunc = context.WithCancel(context.Background())

	return client, nil
}

// Close closes IAM client instance.
func (client *Client) Close() (err error) {
	for _, iam := range client.remoteIAMs {
		iam.Lock()

		if iam.connection != nil {
			log.WithFields(log.Fields{"url": iam.cfg.URL, "nodeID": iam.cfg.NodeID}).Debug("Disconnected from IAM")

			if closeErr := iam.connection.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}

		iam.Unlock()
	}

	return err
}

func (client *Client) GetRemoteNodes() []string {
	nodes := make([]string, 0, len(client.remoteIAMs))

	for node := range client.remoteIAMs {
		nodes = append(nodes, node)
	}

	log.WithFields(log.Fields{"nodes": nodes}).Debug("Get remote nodes")

	return nodes
}

func (client *Client) GetCertTypes(nodeID string) (certTypes []string, err error) {
	if err = client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		response, err := pb.NewIAMProvisioningServiceClient(connection).GetCertTypes(ctx, &pb.GetCertTypesRequest{
			NodeId: nodeID,
		})
		if err != nil {
			return aoserrors.Wrap(err)
		}

		certTypes = response.Types

		return nil
	}); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"nodeID": nodeID, "certTypes": certTypes}).Debug("Get remote cert types")

	return certTypes, nil
}

func (client *Client) SetOwner(nodeID, certType, password string) error {
	return client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID, "certType": certType}).Debug("Set remote IAM owner")

		if _, err := pb.NewIAMProvisioningServiceClient(connection).SetOwner(ctx, &pb.SetOwnerRequest{
			NodeId: nodeID, Type: certType, Password: password,
		}); err != nil {
			return aoserrors.Wrap(err)
		}

		return nil
	})
}

func (client *Client) Clear(nodeID, certType string) error {
	return client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID, "certType": certType}).Debug("Clear remote IAM")

		if _, err := pb.NewIAMProvisioningServiceClient(connection).Clear(ctx, &pb.ClearRequest{
			NodeId: nodeID, Type: certType,
		}); err != nil {
			return aoserrors.Wrap(err)
		}

		return nil
	})
}

func (client *Client) CreateKey(nodeID, certType, subject, password string) (csr []byte, err error) {
	if err = client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID, "certType": certType}).Debug("Create remote IAM key")

		response, err := pb.NewIAMCertificateServiceClient(connection).CreateKey(ctx, &pb.CreateKeyRequest{
			NodeId: nodeID, Subject: subject, Type: certType, Password: password,
		})
		if err != nil {
			return aoserrors.Wrap(err)
		}

		csr = []byte(response.Csr)

		return nil
	}); err != nil {
		return nil, err
	}

	return csr, nil
}

func (client *Client) ApplyCertificate(nodeID, certType string, cert []byte) (certURL string, err error) {
	if err = client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID, "certType": certType}).Debug("Apply remote IAM certificate")

		response, err := pb.NewIAMCertificateServiceClient(connection).ApplyCert(ctx, &pb.ApplyCertRequest{
			NodeId: nodeID, Type: certType, Cert: string(cert),
		})
		if err != nil {
			return aoserrors.Wrap(err)
		}

		certURL = response.CertUrl

		return nil
	}); err != nil {
		return "", err
	}

	return certURL, nil
}

func (client *Client) EncryptDisk(nodeID, password string) error {
	return client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID}).Debug("Encrypt remote IAM disk")

		if _, err := pb.NewIAMProvisioningServiceClient(connection).EncryptDisk(ctx, &pb.EncryptDiskRequest{
			NodeId: nodeID, Password: password,
		}); err != nil {
			return aoserrors.Wrap(err)
		}

		return nil
	})
}

func (client *Client) FinishProvisioning(nodeID string) error {
	return client.sendIAMRequest(nodeID, func(ctx context.Context, connection *grpc.ClientConn) error {
		log.WithFields(log.Fields{"nodeID": nodeID}).Debug("Finish remote IAM provisioning")

		if _, err := pb.NewIAMProvisioningServiceClient(
			connection).FinishProvisioning(ctx, &empty.Empty{}); err != nil {
			return aoserrors.Wrap(err)
		}

		return nil
	})
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (client *Client) getTLSConfig(certStorage string) (*tls.Config, error) {
	certURL, keyURL, err := client.certHandler.GetCertificate(certStorage, nil, "")
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	tlsConfig, err := client.cryptoContext.GetClientMutualTLSConfig(certURL, keyURL)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return tlsConfig, nil
}

func (client *Client) getConnection(iam *remoteIAM) (*grpc.ClientConn, error) {
	if iam.connection != nil {
		iam.connectionTimer.Reset(connectionTimeout)

		return iam.connection, nil
	}

	ctx, cancelFunc := context.WithTimeout(client.ctx, requestTimeout)
	defer cancelFunc()

	log.WithFields(log.Fields{"url": iam.cfg.URL, "nodeID": iam.cfg.NodeID}).Debug("Connecting to IAM...")

	connection, err := grpc.DialContext(ctx, iam.cfg.URL, client.dialOptions...)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{"url": iam.cfg.URL, "nodeID": iam.cfg.NodeID}).Debug("Connected to IAM")

	iam.connection = connection

	iam.connectionTimer = time.AfterFunc(connectionTimeout, func() {
		iam.Lock()
		defer iam.Unlock()

		if err := iam.connection.Close(); err != nil {
			log.Errorf("Error closing connection: %v", err)
		}

		log.WithFields(log.Fields{"url": iam.cfg.URL, "nodeID": iam.cfg.NodeID}).Debug("Disconnected from IAM")

		iam.connection = nil
	})

	return iam.connection, nil
}

func (client *Client) sendIAMRequest(
	nodeID string, requestFunc func(ctx context.Context, connection *grpc.ClientConn) error,
) error {
	iam, ok := client.remoteIAMs[nodeID]
	if !ok {
		return errNodeNotFound
	}

	iam.Lock()
	defer iam.Unlock()

	timeoutCtx, cancelFunc := context.WithTimeout(client.ctx, requestTimeout)
	defer cancelFunc()

	connection, err := client.getConnection(iam)
	if err != nil {
		return err
	}

	if err := requestFunc(timeoutCtx, connection); err != nil {
		return err
	}

	return nil
}
