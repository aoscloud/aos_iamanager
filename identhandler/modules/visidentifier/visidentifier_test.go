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

package visidentifier_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/api/visprotocol"
	"github.com/aoscloud/aos_common/wsserver"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/identhandler"
	"github.com/aoscloud/aos_iamanager/identhandler/modules/visidentifier"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const serverURL = "wss://localhost:443"

/*******************************************************************************
 * Types
 ******************************************************************************/

type clientHandler struct {
	subscriptionID string
	subjects       []string
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var (
	vis    identhandler.IdentModule
	server *wsserver.Server
)

var testHandler = &clientHandler{}

var tmpDir string

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func generateCerts(crtFile string, keyFile string) (err error) {
	crtData := `-----BEGIN CERTIFICATE-----
MIID4zCCAsugAwIBAgIUA4lqVK7Ab4skpwSnvzQWmzrV164wDQYJKoZIhvcNAQEL
BQAwcDElMCMGA1UEAwwcQU9TIHZlaGljbGVzIEludGVybWVkaWF0ZSBDQTENMAsG
A1UECgwERVBBTTEcMBoGA1UECwwTTm92dXMgT3JkbyBTZWNsb3J1bTENMAsGA1UE
BwwES3lpdjELMAkGA1UEBhMCVUEwHhcNMjEwMTA2MTEwODU2WhcNMzEwMTA0MTEw
ODU2WjBQMSMwIQYDVQQDDBpWZWhpY2xlIEluZm9ybWF0aW9uIFNlcnZlcjENMAsG
A1UECgwERVBBTTENMAsGA1UEBwwES3lpdjELMAkGA1UEBhMCVUEwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJLrYf7d5Y6ZFI6ohZhnhL/rrqHDwnScMT
xZLGM0nfC2n5aD7V5Fnm7DYSP57rIpRI3QAHnaBsloJleV5WaPSWO5MQUDgC6EmS
2ycqiqVYcXkLmF6DuagYTuG8WZA/eQswALSA+oCbVOvEO9b3LW6j9TONNS7viORu
4j4Bx94vVvoXqB4nSIgxmf2aunR0hhE9L1Ba/GvCS76uPbq7rBEqMXayTAmgI/in
ggIt9f61ACg9dfjdhpRkEbhwTQGp5F1LcrRO8P9x+T0Vih3ENZNYT7q2HcpxM0Ol
imX2cjIox46h2JVYwG0kfOZ276fR17jgO5+oF5QznXM1tMHDG4PxAgMBAAGjgZQw
gZEwCQYDVR0TBAIwADAdBgNVHQ4EFgQU63wgNk+kHuel75XeVf9V42WR4zIwHwYD
VR0jBBgwFoAUzIhH1KOyEXhnmvEj0rJmEPoKOMIwCwYDVR0PBAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMCIGA1UdEQQbMBmCBnd3d2l2aYIJbG9jYWxob3N0hwR/
AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCY80mthhRCRi33YJRoMKUI1BwPWg8/46Lh
E1RKcNZ4M0TNB6swesEiqn0oTNcaXz4N0NVRjmUwYQxbRoYCoodcYJKtKf41cDxL
uJTnVgTD9sz2B03RjhQS+SoavJom3lyGfUs4n7LN39+MinVDbgmrf/QdtceQoPvq
XCAU+jexUpxjMxgNTMswRPXqU694/ED3VfAAzjnS3m4rbTrdHuWF+yC50XOU8ReH
dpmTzzazYaepK96NBbNhGhj3Esiguv7DqaLdivhPUCzjQtGsIbEKshfD0sDyN4a/
dQujfabxICRxNHO/4d2dSZ5BWDZIDPjZm3K3btL3+Z6yXYePBx3s
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIJAO2BVuwqJLb8MA0GCSqGSIb3DQEBCwUAMFQxGTAXBgNV
BAMMEEFvUyBTZWNvbmRhcnkgQ0ExDTALBgNVBAoMBEVQQU0xDDAKBgNVBAsMA0Fv
UzENMAsGA1UEBwwES3lpdjELMAkGA1UEBhMCVUEwHhcNMTkwMzIxMTMyMjQwWhcN
MjUwMzE5MTMyMjQwWjBwMSUwIwYDVQQDDBxBT1MgdmVoaWNsZXMgSW50ZXJtZWRp
YXRlIENBMQ0wCwYDVQQKDARFUEFNMRwwGgYDVQQLDBNOb3Z1cyBPcmRvIFNlY2xv
cnVtMQ0wCwYDVQQHDARLeWl2MQswCQYDVQQGEwJVQTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKs2DANC2BAGU/rzUpOy3HpcShNdC7+vjcZ2fX6kFF9k
RZumS58dHQjj+UW6VQXFd5QS1Bb6lL/psc7svYEE4c212fWkkw84Un+ZibbIQvsF
LfAz9lqYLtzJPY3bjHRwe9bZUjO1YNxjxupB6o0R7yRGiFVA7ajrSkpNG8xrCVg6
OkN/B6hGXfv1Vn+t7lo3+JAGhEJ+/3sQ6lmyLBTtnr+qMUDwWDqKarqY9gBZbGyY
K+Jj1M0axtUtO2wNFa0UCK36aFaA/0DdoltpnenCyIngKmDBYJPwKQiqOoKEtKan
tTIa5uM6PJgrhDPjfquODfbxqxZBYnY4+WUTWNpwa7sCAwEAAaN8MHowDAYDVR0T
BAUwAwEB/zAdBgNVHQ4EFgQUzIhH1KOyEXhnmvEj0rJmEPoKOMIwHwYDVR0jBBgw
FoAUNrDxTEYV6uDVs6xHNU77q9zVmMowCwYDVR0PBAQDAgGmMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAF3YtoIs6HrcC
XXJH//FGm4SlWGfhQ7l4k2PbC4RqrZvkMMIci7oT2xfdIAzbPUBiaVXMEw7HR7eI
iOqRzjR2ZUqIz3VD6fGVyw5Y3JLqMuT7DuirQ9BWeBTf+BXm40cvLsnWbQD7r6RD
x1a8E9uOLdt7/9C2utoQVdAZLu7UgUqRyFVeF8zHT98INDtYi8bp8nZ/de64fZbN
5pmBi2OdQGcvXUj/SRt/4OCmRqBqrYjgSl7TaAlyvf4/xk2uBG4AaKFZWWlth244
KgfaSRGKUZuvyQwTKerc8AwUFu5r3tZwAlwT9dyRM1fg+EGbmKaadyegb3AtItyN
d2r/FFIYWg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIJAO2BVuwqJLb4MA0GCSqGSIb3DQEBCwUAMIGNMRcwFQYD
VQQDDA5GdXNpb24gUm9vdCBDQTEpMCcGCSqGSIb3DQEJARYadm9sb2R5bXlyX2Jh
YmNodWtAZXBhbS5jb20xDTALBgNVBAoMBEVQQU0xHDAaBgNVBAsME05vdnVzIE9y
ZG8gU2VjbG9ydW0xDTALBgNVBAcMBEt5aXYxCzAJBgNVBAYTAlVBMB4XDTE5MDMy
MTEzMTQyNVoXDTI1MDMxOTEzMTQyNVowVDEZMBcGA1UEAwwQQW9TIFNlY29uZGFy
eSBDQTENMAsGA1UECgwERVBBTTEMMAoGA1UECwwDQW9TMQ0wCwYDVQQHDARLeWl2
MQswCQYDVQQGEwJVQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyD
uKMpBZN/kQFHzKo8N8y1EoPgG5sazSRe0O5xL7lm78hBmp4Vpsm/BYSI8NElkxdO
TjqQG6KK0HAyCCfQJ7MnI3G/KnJ9wxD/SWjye0/Wr5ggo1H3kFhSd9HKtuRsZJY6
E4BSz4yzburCIILC4ZvS/755OAAFX7g1IEsPeKh8sww1oGLL0xeg8W0CWmWO9PRn
o5Dl7P5QHR02BKrEwZ/DrpSpsE+ftTczxaPp/tzqp2CDGWYT5NoBfxP3W7zjKmTC
ECVgM/c29P2/AL4J8xXydDlSujvE9QG5g5UUz/dlBbVXFv0cK0oneADe0D4aRK5s
MH2ZsVFaaZAd2laa7+MCAwEAAaN8MHowDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU
NrDxTEYV6uDVs6xHNU77q9zVmMowHwYDVR0jBBgwFoAUdEoYczrjPeQYQ9JlsQtY
/iqxOlIwCwYDVR0PBAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjANBgkqhkiG9w0BAQsFAAOCAQEAe1IT/RhZ690PIBlkzLDutf0zfs2Ei6jxTyCY
xiEmTExrU0qCZECxu/8Up6jpgqHN5upEdL/kDWwtogn0K0NGBqMNiDyc7f18rVvq
/5nZBl7P+56h5DcuLJsUb3tCC5pIkV9FYeVCg+Ub5c59b3hlFpqCmxSvDzNnRZZc
r+dInAdjcVZWmAisIpoBPrtCrqGydBtP9wy5PPxUW2bwhov4FV58C+WZ7GOLMqF+
G0wAlE7RUWvuUcKYVukkDjAg0g2qE01LnPBtpJ4dsYtEJnQknJR4swtnWfCcmlHQ
rbDoi3MoksAeGSFZePQKpht0vWiimHFQCHV2RS9P8oMqFhZN0g==
-----END CERTIFICATE-----
`

	keyData := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyS62H+3eWOmRSOqIWYZ4S/666hw8J0nDE8WSxjNJ3wtp+Wg+
1eRZ5uw2Ej+e6yKUSN0AB52gbJaCZXleVmj0ljuTEFA4AuhJktsnKoqlWHF5C5he
g7moGE7hvFmQP3kLMAC0gPqAm1TrxDvW9y1uo/UzjTUu74jkbuI+AcfeL1b6F6ge
J0iIMZn9mrp0dIYRPS9QWvxrwku+rj26u6wRKjF2skwJoCP4p4ICLfX+tQAoPXX4
3YaUZBG4cE0BqeRdS3K0TvD/cfk9FYodxDWTWE+6th3KcTNDpYpl9nIyKMeOodiV
WMBtJHzmdu+n0de44DufqBeUM51zNbTBwxuD8QIDAQABAoIBAQDGrjzql21ofXIf
go8ZarVOx8gr/6pgWnYvBoWG+4vOnGUSDCNR9OvcJBbaOr5lFIdA1hB7dO3Dj3hD
YnMJ/yjdXQRFrhNCu8g9IfUyDC5yg82458cfa7BYIT7JVeIg7RdhVrDsV3e+70TP
TRFklheYEEXTBFzP7m86GnCGLa59LDWgxZ0KwdWZCyoRo+lCfBOQDulwEyTnnApC
jCQYFg6zw552h4FjlpB1dtMIzeDRUBUpzHT1GeHUybaAvptnMB9Wk1FI504YTOJM
6WUR8+AHDLUyEL/+VMEulpDybpVAjFototN/BEZVXahrqO1tX34uAgfM7Ag0rwv0
kaAqLDCJAoGBAO3BMisiJRX5Vo33a+tkzHCksJPXaZedqnfWzdmDLlv6wvAUx7wU
GY8rB5tcGYpYeK/VPYQQtY3ml2tzZJ0kIYlXwbTMySS9fJ7if9ukSGYxxhc188vi
lgRfZaBueZ7Y1ABVEwfGkLsuWT0PcQZO8a2N0RCI5EpK6kBfJkcVp6IHAoGBANif
CXpM6s3CdBMuhTYDQqhCu5Buavpzr7Tap7YbLFWn2x2rrVwtd78Wo0xcGReMODXo
5f3U+iJFI54SRTWAdG4lSAXcIVsK9JUMJOLPgogSt+JNE5tP90wXjuVwbjGeLrOj
gli+Xmkm/P6rStvN88Vqo13x4Vo/8VnS50hPgMxHAoGAfivHjuJY4fdm+oHyEIJ2
h9SuLFbln2M5Ys1ogmS+Rmul5bhxYpscEUEZkVXn6+YVbeJw+dPQNVTIyGn9W/Mf
pP4gOu1uVQQFzV+P0KS3ExyY7hpgnbNKP1nM2b2m5yhUITUEm1zB08O98cxvA5UD
ZkHbT7YFyHNHKxAThSe1xSMCgYEAvDtWDQQRdMJoAtMFxi2HGpcCTTrlksQ8BjeK
TF/IYpX9fQbVGagYyd9t/sh4tVGO9qluUOdkg6r4jD7sDNWWVq/mqdDi2y3l4i4v
TzdqAbviNa8sPmV6SpCeBxlvZ4ZAprCKb3rcpxrN9K372oxYK0/CrbulSrsNijQN
7XPIQ7kCgYBsVwnAfcRm3VE3oA6tVWUed7RExMTBM1YxEoo7eTyEhBiq1cHSowBT
QRUogt5UZOrxFviUMF3wtG/D7hOlq0AFdxsstV7BGdOrlZEvdCKZ1/U8Ybl/Q5PV
IOdqNfMS0yqDTM/Dl3BUwVPzjXtxXx7ARGTi3sPyxu/i54uqA2DIww==
-----END RSA PRIVATE KEY-----`

	if err = os.WriteFile(crtFile, []byte(crtData), 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	if err = os.WriteFile(keyFile, []byte(keyData), 0o600); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func setup() (err error) {
	if tmpDir, err = os.MkdirTemp("", "iam_"); err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	crtFile := path.Join(tmpDir, "crt.pem")
	keyFile := path.Join(tmpDir, "key.pem")

	if err = generateCerts(crtFile, keyFile); err != nil {
		log.Fatalf("Can't generate cert files: %s", err)
	}

	url, err := url.Parse(serverURL)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if server, err = wsserver.New("TestServer", url.Host, crtFile, keyFile, testHandler); err != nil {
		return aoserrors.Wrap(err)
	}

	time.Sleep(1 * time.Second)

	if vis, err = visidentifier.New([]byte(
		`{"VisServer": "wss://localhost:443", "CaCertFile": "` + crtFile + `"}`)); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func cleanup() (err error) {
	if err = os.RemoveAll(tmpDir); err != nil {
		log.Errorf("Can't remove tmp dir: %s", err)
	}

	if err = vis.Close(); err != nil {
		return aoserrors.Wrap(err)
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

func TestGetUnitModel(t *testing.T) {
	unitModel, err := vis.GetUnitModel()
	if err != nil {
		t.Fatalf("Error getting unit model: %s", err)
	}

	if unitModel == "" {
		t.Fatalf("Wrong unit model value: %s", unitModel)
	}
}

func TestGetSubjects(t *testing.T) {
	testHandler.subjects = []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	subjects, err := vis.GetSubjects()
	if err != nil {
		t.Fatalf("Error getting subjects: %s", err)
	}

	if !reflect.DeepEqual(subjects, testHandler.subjects) {
		t.Errorf("Wrong subjects value: %s", subjects)
	}
}

func TestSubjectsChanged(t *testing.T) {
	newSubjects := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}

	go testHandler.SubjectsChangeNotification(newSubjects)

	select {
	case subjects := <-vis.SubjectsChangedChannel():
		if !reflect.DeepEqual(newSubjects, subjects) {
			t.Errorf("Wrong subjects value: %s", subjects)
		}

	case <-time.After(5 * time.Second):
		t.Error("Waiting for subjects changed timeout")
	}

	subjects, err := vis.GetSubjects()
	if err != nil {
		t.Fatalf("Error getting subjects: %s", err)
	}

	if !reflect.DeepEqual(subjects, newSubjects) {
		t.Errorf("Wrong subjects value: %s", subjects)
	}
}

/*******************************************************************************
 * Interfaces
 ******************************************************************************/

func (handler *clientHandler) ProcessMessage(
	client *wsserver.Client, messageType int, message []byte,
) (response []byte, err error) {
	var header visprotocol.MessageHeader

	if err = json.Unmarshal(message, &header); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	var rsp interface{}

	switch header.Action {
	case visprotocol.ActionSubscribe:
		handler.subscriptionID = uuid.New().String()

		rsp = &visprotocol.SubscribeResponse{
			MessageHeader:  header,
			SubscriptionID: handler.subscriptionID,
		}

	case visprotocol.ActionUnsubscribe:
		var unsubscribeReq visprotocol.UnsubscribeRequest

		if err = json.Unmarshal(message, &unsubscribeReq); err != nil {
			return nil, aoserrors.Wrap(err)
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
			MessageHeader: header,
		}

		if err = json.Unmarshal(message, &getReq); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		switch getReq.Path {
		case "Attribute.Vehicle.VehicleIdentification.VIN":
			getRsp.Value = map[string]string{getReq.Path: "VIN1234567890"}

		case "Attribute.Aos.UnitModel":
			getRsp.Value = map[string]string{getReq.Path: "testUnitModel:1.0"}

		case "Attribute.Aos.Subjects":
			getRsp.Value = map[string][]string{getReq.Path: handler.subjects}
		}

		rsp = &getRsp

	case visprotocol.ActionSet:
		var setReq visprotocol.SetRequest

		setRsp := visprotocol.SetResponse{
			MessageHeader: header,
		}

		rsp = &setRsp

		if err = json.Unmarshal(message, &setReq); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		switch setReq.Path {
		case "Attribute.Vehicle.VehicleIdentification.VIN":
			setRsp.Error = &visprotocol.ErrorInfo{Message: "readonly path"}

		case "Attribute.Aos.UnitModel":
			setRsp.Error = &visprotocol.ErrorInfo{Message: "readonly path"}

		case "Attribute.Aos.Subjects":
			handler.subjects = nil

			subjects, ok := setReq.Value.([]interface{})
			if !ok {
				return nil, aoserrors.New("incorrect type for subjects")
			}

			for _, subjectElement := range subjects {
				if subject, ok := subjectElement.(string); ok {
					handler.subjects = append(handler.subjects, subject)
				}
			}

			go handler.SubjectsChangeNotification(handler.subjects)
		}

	default:
		return nil, aoserrors.New("unknown action")
	}

	if response, err = json.Marshal(rsp); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return response, nil
}

func (handler *clientHandler) SubjectsChangeNotification(subjects []string) {
	if handler.subscriptionID != "" {
		message, err := json.Marshal(&visprotocol.SubscriptionNotification{
			Action:         "subscription",
			SubscriptionID: handler.subscriptionID,
			Value:          map[string][]string{"Attribute.Aos.Subjects": subjects},
		})
		if err != nil {
			log.Errorf("Error marshal request: %s", err)
		}

		clients := server.GetClients()

		for _, client := range clients {
			if err := client.SendMessage(websocket.TextMessage, message); err != nil {
				log.Errorf("Error sending message: %s", err)
			}
		}
	}
}

func (handler *clientHandler) ClientConnected(client *wsserver.Client) {
}

func (handler *clientHandler) ClientDisconnected(client *wsserver.Client) {
}
