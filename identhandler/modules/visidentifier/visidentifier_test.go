// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Renesas Inc.
// Copyright 2019 EPAM Systems Inc.
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

package visidentifier_test

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/visprotocol"
	"gitpct.epam.com/epmd-aepr/aos_common/wsserver"

	"aos_iamanager/identhandler"
	"aos_iamanager/identhandler/modules/visidentifier"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const serverURL = "wss://localhost:8088"

/*******************************************************************************
 * Types
 ******************************************************************************/

type clientHandler struct {
	subscriptionID string
	users          []string
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var vis identhandler.IdentModule
var server *wsserver.Server

var testHandler = &clientHandler{}

var tmpDir string

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func generateCerts(crtFile string, keyFile string) (err error) {
	crtData := `-----BEGIN CERTIFICATE-----
MIID2jCCAsKgAwIBAgIJAI3IBJkXKkPqMA0GCSqGSIb3DQEBCwUAMIGWMSAwHgYD
VQQDDBdGdXNpb24gU2Vjb25kYXJ5IFNpZ25lcjEpMCcGCSqGSIb3DQEJARYadm9s
b2R5bXlyX2JhYmNodWtAZXBhbS5jb20xDTALBgNVBAoMBEVQQU0xHDAaBgNVBAsM
E05vdnVzIE9yZG8gU2VjbG9ydW0xDTALBgNVBAcMBEt5aXYxCzAJBgNVBAYTAlVB
MB4XDTE4MDUxODEzMzYwN1oXDTIxMDIxMTEzMzYwN1owgZkxIzAhBgNVBAMMGlZl
aGljbGUgSW5mb3JtYXRpb24gU2VydmVyMSkwJwYJKoZIhvcNAQkBFhp2b2xvZHlt
eXJfYmFiY2h1a0BlcGFtLmNvbTENMAsGA1UECgwERVBBTTEcMBoGA1UECwwTTm92
dXMgT3JkbyBTZWNsb3J1bTENMAsGA1UEBwwES3lpdjELMAkGA1UEBhMCVUEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXz3xOwdbQd5GVygyognsEe4e+
Jo8YoD9uxUWMZJsEj560qM5DRIj2ToTWomIDcnZspBYUxdKx5qnUxHTNVtFsYMzL
pjoDUggMJQ9zP5Zo6o+IQ+mI/FnbNQfItm6yac4fuAG3XqUUjsbVhgQI5slI0YHU
yQZ9sAOidzXXXcYRt4xHp4r+wxqhGQA2ymSe5phcZcZkEh8IA3zpToeU4dys5wtV
b66wVhGSbsPzbq5d0MMSW17pLc895Py3b1pugp0yXbRPWLjJa7I7L59xg+CGKCy5
Z/Pwz27xKRlMmuY1dCK6zECBPxw8o3e/TORgireZckaq3seep0cDLYLAoXobAgMB
AAGjJjAkMCIGA1UdEQQbMBmCCWxvY2FsaG9zdIcEfwAAAYIGd3d3aXZpMA0GCSqG
SIb3DQEBCwUAA4IBAQBBJLl3daHVxT7HGKH0TVMY3XrAXyLwzSGUJZJ4RkK29/SW
cMZZ/oVG+bI8ZzUN9VJTSnGC/HLNCR9A+IXHDdnmMroq/e4+5Y1noIvNBTMoQ4GW
ySur9j0CXNlfEZLcVhLKAI0a/2+xQ9ZimMd3ItmsbViKTrMjojAMAL6h4mQNEsai
P48/f4oceqeooK+aBsdjV9Dugba+Keeh7z2eDrPRRRgmp5gE0zrqctmeOGrI4BwZ
T4YEIylNzzfsQjI9DZ3pNKVQ6eO/ENdysnUnt0LotsNJxVDn0e//CsyFQW3/15ut
vr5oiEzRwJIxDmcsatHE52YIi7Mcn5q5XK5Er90R
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEFjCCAv6gAwIBAgIJAOvRuvJcsWhNMA0GCSqGSIb3DQEBCwUAMIGNMRcwFQYD
VQQDDA5GdXNpb24gUm9vdCBDQTEpMCcGCSqGSIb3DQEJARYadm9sb2R5bXlyX2Jh
YmNodWtAZXBhbS5jb20xDTALBgNVBAoMBEVQQU0xHDAaBgNVBAsME05vdnVzIE9y
ZG8gU2VjbG9ydW0xDTALBgNVBAcMBEt5aXYxCzAJBgNVBAYTAlVBMB4XDTE4MDQw
NTE2MzE0NVoXDTIwMTIzMDE2MzE0NVowgZYxIDAeBgNVBAMMF0Z1c2lvbiBTZWNv
bmRhcnkgU2lnbmVyMSkwJwYJKoZIhvcNAQkBFhp2b2xvZHlteXJfYmFiY2h1a0Bl
cGFtLmNvbTENMAsGA1UECgwERVBBTTEcMBoGA1UECwwTTm92dXMgT3JkbyBTZWNs
b3J1bTENMAsGA1UEBwwES3lpdjELMAkGA1UEBhMCVUEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC8g7ijKQWTf5EBR8yqPDfMtRKD4BubGs0kXtDucS+5
Zu/IQZqeFabJvwWEiPDRJZMXTk46kBuiitBwMggn0CezJyNxvypyfcMQ/0lo8ntP
1q+YIKNR95BYUnfRyrbkbGSWOhOAUs+Ms27qwiCCwuGb0v++eTgABV+4NSBLD3io
fLMMNaBiy9MXoPFtAlpljvT0Z6OQ5ez+UB0dNgSqxMGfw66UqbBPn7U3M8Wj6f7c
6qdggxlmE+TaAX8T91u84ypkwhAlYDP3NvT9vwC+CfMV8nQ5Uro7xPUBuYOVFM/3
ZQW1Vxb9HCtKJ3gA3tA+GkSubDB9mbFRWmmQHdpWmu/jAgMBAAGjbjBsMB0GA1Ud
DgQWBBQ2sPFMRhXq4NWzrEc1Tvur3NWYyjAMBgNVHRMEBTADAQH/MAsGA1UdDwQE
AwIBBjAlBgNVHREEHjAcgRp2b2xvZHlteXJfYmFiY2h1a0BlcGFtLmNvbTAJBgNV
HRIEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCCi5c7fbUiUP5az79wzRM/1zucRuyh
Lg2DUPQpaj6Oq16i+ts7/y6lSLOTWPo09/q7G+WWiLBjSwE4YAnnd/wYj+mhS7Hx
4J/w3goHqLHDj7XnO7iH44s389WXe6+3ZQIeMXG+jT57dacGaZa3UhEwm4Wn99Ka
eHYJVaDfI4kwgThILOCv4Apls/Uwfic7Vv3jptPwIolim936FtlFehEYHJG5RuHX
0OakitfOUUfv8zRZuSLLJqAfwA1Sfub22TFqg8pFBpZVOYIYI4lztC5R/OODSWln
hY9XlDkj2QmX4VyKbjmkyIaZdy3Wyr/w+lopl7f1y7ODFK5NCPIvgPoy
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDnTCCAoWgAwIBAgIJAMA7n5vmXZwoMA0GCSqGSIb3DQEBCwUAMIGNMRcwFQYD
VQQDDA5GdXNpb24gUm9vdCBDQTEpMCcGCSqGSIb3DQEJARYadm9sb2R5bXlyX2Jh
YmNodWtAZXBhbS5jb20xDTALBgNVBAoMBEVQQU0xHDAaBgNVBAsME05vdnVzIE9y
ZG8gU2VjbG9ydW0xDTALBgNVBAcMBEt5aXYxCzAJBgNVBAYTAlVBMB4XDTE4MDQw
NTE2MjY1M1oXDTI2MDYyMjE2MjY1M1owgY0xFzAVBgNVBAMMDkZ1c2lvbiBSb290
IENBMSkwJwYJKoZIhvcNAQkBFhp2b2xvZHlteXJfYmFiY2h1a0BlcGFtLmNvbTEN
MAsGA1UECgwERVBBTTEcMBoGA1UECwwTTm92dXMgT3JkbyBTZWNsb3J1bTENMAsG
A1UEBwwES3lpdjELMAkGA1UEBhMCVUEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC+K2ow2HO7+SUVfOq5tTtmHj4LQijHJ803mLk9pkPef+Glmeyp9HXe
jDlQC04MeovMBeNTaq0wibf7qas9niXbeXRVzheZIFziMXqRuwLqc0KXdDxIDPTb
TW3K0HE6M/eAtTfn9+Z/LnkWt4zMXasc02hvufsmIVEuNbc1VhrsJJg5uk88ldPM
LSF7nff9eYZTHYgCyBkt9aL+fwoXO6eSDSAhjopX3lhdidkM+ni7EOhlN7STmgDM
WKh9nMjXD5f28PGhtW/dZvn4SzasRE5MeaExIlBmhkWEUgVCyP7LvuQGRUPK+NYz
FE2CLRuirLCWy1HIt9lLziPjlZ4361mNAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
ADNRbu1A7FsBjkAClXbvOJtAGOqywR/rXFY5WJsHAgXq7Hc//z3obHLt759WvK7I
KjJbcEbpP0Kg4+GYrJRfvhN/7HKw09dUHr7FujMmAuctBsTsvFOBfP4NvdU03Mn3
LfOuNVcOUgHw1A1hUIDfEcY5U3gO8risWCUnhUzD9Dt3aR46rKE3J8PQa2vuSmfX
cPfAjCo/pBB2V23BEY5xJArQ7bNPDLxC8ohMW8S/TVsH/7ErlrmL8OL0QY/xv1vx
Oow7m58IFHPKLEbVvgkQ3sSqEjmBzwr/7cjhU5NiI+AwiB/el+y8BEV1WbbIQVip
IfIfPNVut26yQeJrRCL7lB4=
-----END CERTIFICATE-----`

	keyData := `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA1898TsHW0HeRlcoMqIJ7BHuHviaPGKA/bsVFjGSbBI+etKjO
Q0SI9k6E1qJiA3J2bKQWFMXSseap1MR0zVbRbGDMy6Y6A1IIDCUPcz+WaOqPiEPp
iPxZ2zUHyLZusmnOH7gBt16lFI7G1YYECObJSNGB1MkGfbADonc1113GEbeMR6eK
/sMaoRkANspknuaYXGXGZBIfCAN86U6HlOHcrOcLVW+usFYRkm7D826uXdDDElte
6S3PPeT8t29aboKdMl20T1i4yWuyOy+fcYPghigsuWfz8M9u8SkZTJrmNXQiusxA
gT8cPKN3v0zkYIq3mXJGqt7HnqdHAy2CwKF6GwIDAQABAoIBAQCIYmazuwqPulC2
Mfdn8vXdclfp0qJyNKuBzIfUXqwc6Mqqb1fS6RgJWLvYjMyWUxsGM3iE7jPmG9jO
Ts1mC2zUKiSius1E1e2iBzXJZrEeYsYMnqaS3K/Iua3OqYQxmm4aW4YyJUz8PfLo
dAZOvdMNAuIi4FwKyFazsNTE401OWeDJFilgBCFI9iypuukl95pIIxsIi+Cg94Jk
nYqZgksi4qLPL5a+HOlBbf5fRGsI0D8RWNpEXvvbC6Ey89UYIoDT8az3Wg8aanAq
W6mFGABeu5/PxhpL62ciVSvlUG+srmmQ40vhkre39FvCz1DatSUywJDuO+JgKpNX
UbvWz4mRAoGBAPGZU0MM6mjYNmIqYCBqBoOpNcbHdRxpNQHbfTscvwg5k/oYq92N
/TxU7gsvkdK+q/s8erd58sKUWSANHAADer6TL+1ZORhJulxH5IDDhmwRLzohZyOi
NvJhB4eJaZgjfkJMwrzJqsU7jIqd/WfATAiOBRfEdSqDTg25wd4Qq+SDAoGBAOSs
pGJpKxLO0PEidACXyr+hx4A13D28mr/V9b84TIkYqyrjx74JXx98GL1IJPbJL3Mm
zm21Wlx3KWWEHT5+C80NcgXHdOERtDmRfFvWGg08OXGBq+9tq2meqS4PMUyBcOvJ
6bbqWlwkiY4tDdJR2DcSQ6FLMgxweVyuGMRZdBCJAoGBAI2n0rPrrL2QmEJyii43
PF6SJh/I7xebcCMIqKKyNigCaosnUA31pNdtDK2uVJf2iCwkx+cwL3B7Ps6WISa4
440+C8nkmJ9vCz/0PzxoaDaQ1NoGn8y63fC7h4imvy0fEnaZP00mCWTfh4X3II9m
pq4VZ1MKM5CbsHZHxi4IJGE1AoGBAJQNTrTEgHXB3zdv5gkIPeWKWb8hoAF8nfh8
D4qJacwNY6z2IrlgGe0pjF7oWb5KDWWRh28yTlm1cODgA4sVUpClFuC0/XBG5Res
oQZYfS96gXqCyQ3QRH2ykrhWb8WnvLN8W8vouS4VHdYmR1+XS9SEB7NjGvlAzOJ7
eV+Oxv15AoGBAJ09+rlOrNLo7UbiOtqHxH1NF7ddfiL9Q+wB7D9ZMmMg5yIeHNja
YMStqYbkcdCL/lrwyOK7evQyoCG+skUotWWBZgE+AJxtrJzuCU4mxECOe2Q6Avkz
DHlSgmjxDy+SeyiLTqNrrDaSKW3RNlMwkroX7aKjChlTnGJ7pS2DjCFG
-----END RSA PRIVATE KEY-----`

	if err = ioutil.WriteFile(crtFile, []byte(crtData), 0644); err != nil {
		return err
	}

	if err = ioutil.WriteFile(keyFile, []byte(keyData), 0644); err != nil {
		return err
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = ioutil.TempDir("", "iam_"); err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	crtFile := path.Join(tmpDir, "crt.pem")
	keyFile := path.Join(tmpDir, "key.pem")

	if err = generateCerts(crtFile, keyFile); err != nil {
		log.Fatalf("Can't generate cert files: %s", err)
	}

	url, err := url.Parse(serverURL)
	if err != nil {
		return err
	}

	if server, err = wsserver.New("TestServer", url.Host, crtFile, keyFile, testHandler); err != nil {
		return err
	}

	time.Sleep(1 * time.Second)

	if vis, err = visidentifier.New([]byte(`{"VisServer": "wss://localhost:8088"}`)); err != nil {
		return err
	}

	return nil
}

func cleanup() (err error) {
	if err = os.RemoveAll(tmpDir); err != nil {
		log.Errorf("Can't remove tmp dir: %s", err)
	}

	if err = vis.Close(); err != nil {
		return err
	}

	return nil
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		log.Fatalf("Setup error: %s", err)
	}

	ret := m.Run()

	if err := cleanup(); err != nil {
		log.Fatalf("Cleanup error: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestGetSystemID(t *testing.T) {
	systemID, err := vis.GetSystemID()
	if err != nil {
		t.Fatalf("Error getting system ID: %s", err)
	}

	if systemID == "" {
		t.Fatalf("Wrong system ID value: %s", systemID)
	}
}

func TestGetUsers(t *testing.T) {
	testHandler.users = []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	users, err := vis.GetUsers()
	if err != nil {
		t.Fatalf("Error getting users: %s", err)
	}

	if !reflect.DeepEqual(users, testHandler.users) {
		t.Errorf("Wrong users value: %s", users)
	}
}

func TestUsersChanged(t *testing.T) {
	newUsers := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	if err := vis.SetUsers(newUsers); err != nil {
		t.Fatalf("Can't set users: %s", err)
	}

	select {
	case users := <-vis.UsersChangedChannel():
		if !reflect.DeepEqual(newUsers, users) {
			t.Errorf("Wrong users value: %s", users)
		}

	case <-time.After(5 * time.Second):
		t.Error("Waiting for users changed timeout")
	}
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

func (handler *clientHandler) ProcessMessage(client *wsserver.Client, messageType int, message []byte) (response []byte, err error) {
	var header visprotocol.MessageHeader

	if err = json.Unmarshal(message, &header); err != nil {
		return nil, err
	}

	var rsp interface{}

	switch header.Action {
	case visprotocol.ActionSubscribe:
		handler.subscriptionID = uuid.New().String()

		rsp = &visprotocol.SubscribeResponse{
			MessageHeader:  header,
			SubscriptionID: handler.subscriptionID}

	case visprotocol.ActionUnsubscribe:
		var unsubscribeReq visprotocol.UnsubscribeRequest

		if err = json.Unmarshal(message, &unsubscribeReq); err != nil {
			return nil, err
		}

		unsubscribeRsp := visprotocol.UnsubscribeResponse{
			MessageHeader:  header,
			SubscriptionID: unsubscribeReq.SubscriptionID,
		}

		rsp = &unsubscribeRsp

		if unsubscribeReq.SubscriptionID != handler.subscriptionID {
			unsubscribeRsp.Error = &visprotocol.ErrorInfo{Message: "subscription ID not found"}
			break
		}

		handler.subscriptionID = ""

	case visprotocol.ActionUnsubscribeAll:
		handler.subscriptionID = ""

		rsp = &visprotocol.UnsubscribeAllResponse{MessageHeader: header}

	case visprotocol.ActionGet:
		var getReq visprotocol.GetRequest

		getRsp := visprotocol.GetResponse{
			MessageHeader: header}

		if err = json.Unmarshal(message, &getReq); err != nil {
			return nil, err
		}

		switch getReq.Path {
		case "Attribute.Vehicle.VehicleIdentification.VIN":
			getRsp.Value = map[string]string{getReq.Path: "VIN1234567890"}

		case "Attribute.Vehicle.UserIdentification.Users":
			getRsp.Value = map[string][]string{getReq.Path: handler.users}
		}

		rsp = &getRsp

	case visprotocol.ActionSet:
		var setReq visprotocol.SetRequest

		setRsp := visprotocol.SetResponse{
			MessageHeader: header}

		rsp = &setRsp

		if err = json.Unmarshal(message, &setReq); err != nil {
			return nil, err
		}

		switch setReq.Path {
		case "Attribute.Vehicle.VehicleIdentification.VIN":
			setRsp.Error = &visprotocol.ErrorInfo{Message: "readonly path"}

		case "Attribute.Vehicle.UserIdentification.Users":
			handler.users = nil

			for _, claim := range setReq.Value.([]interface{}) {
				handler.users = append(handler.users, claim.(string))
			}

			if handler.subscriptionID != "" {
				go func() {
					message, err := json.Marshal(&visprotocol.SubscriptionNotification{
						Action:         "subscription",
						SubscriptionID: handler.subscriptionID,
						Value:          map[string][]string{"Attribute.Vehicle.UserIdentification.Users": handler.users}})
					if err != nil {
						log.Errorf("Error marshal request: %s", err)
					}

					clients := server.GetClients()

					for _, client := range clients {
						if err := client.SendMessage(websocket.TextMessage, message); err != nil {
							log.Errorf("Error sending message: %s", err)
						}
					}
				}()
			}
		}

	default:
		return nil, errors.New("unknown action")
	}

	if response, err = json.Marshal(rsp); err != nil {
		return
	}

	return response, nil
}

func (handler *clientHandler) ClientConnected(client *wsserver.Client) {

}

func (handler *clientHandler) ClientDisconnected(client *wsserver.Client) {

}
