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

package visidentifier

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/api/visprotocol"
	"github.com/aoscloud/aos_common/wsclient"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_iamanager/identhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	subjectsChangedChannelSize = 1
)

const reconnectTimeout = 10 * time.Second

const (
	vinVISPath      = "Attribute.Vehicle.VehicleIdentification.VIN"
	boardModelPath  = "Attribute.Aos.BoardModel"
	subjectsVISPath = "Attribute.Aos.Subjects"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// Instance vis identifier instance.
type Instance struct {
	config instanceConfig

	subjectChangedChannel chan []string

	wsClient *wsclient.Client

	vin        string
	boardModel string
	subjects   []string

	subscribeMap sync.Map

	sync.Mutex
	wg sync.WaitGroup
}

type instanceConfig struct {
	VISServer        string `json:"visServer"`
	CaCertFile       string `json:"caCertFile,omitempty"`
	WebSocketTimeout int    `json:"webSocketTimeout,omitempty"`
}

/*******************************************************************************
 * init
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new vis identifier instance.
func New(configJSON json.RawMessage) (identifier identhandler.IdentModule, err error) {
	log.Info("Create VIS identification instance")

	instance := &Instance{}

	if err = json.Unmarshal(configJSON, &instance.config); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if instance.wsClient, err = wsclient.New(
		"VIS",
		wsclient.ClientParam{
			CaCertFile: instance.config.CaCertFile, WebSocketTimeout: time.Duration(instance.config.WebSocketTimeout),
		},
		instance.messageHandler); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	instance.subjectChangedChannel = make(chan []string, subjectsChangedChannelSize)

	instance.wg.Add(1)

	go instance.handleConnection(instance.config.VISServer)

	return instance, nil
}

// Close closes vis identifier instance.
func (instance *Instance) Close() (err error) {
	log.Info("Close VIS identification instance")

	req := visprotocol.UnsubscribeAllRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionUnsubscribeAll,
			RequestID: wsclient.GenerateRequestID(),
		},
	}

	var rsp visprotocol.UnsubscribeAllResponse

	var retErr error

	if err = instance.wsClient.SendRequest("RequestID", req.RequestID, &req, &rsp); err != nil && retErr == nil {
		retErr = err
	}

	if err = instance.wsClient.Close(); err != nil && retErr == nil {
		retErr = err
	}

	return aoserrors.Wrap(retErr)
}

// GetSystemID returns the system ID.
func (instance *Instance) GetSystemID() (systemID string, err error) {
	instance.wg.Wait()

	rsp, err := instance.sendGetRequest(vinVISPath)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	value, err := getValueByPath(vinVISPath, rsp.Value)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	var ok bool

	if instance.vin, ok = value.(string); !ok {
		return "", aoserrors.New("wrong VIN type")
	}

	log.WithField("VIN", instance.vin).Debug("Get VIN")

	return instance.vin, aoserrors.Wrap(err)
}

// GetBoardModel returns the board model.
func (instance *Instance) GetBoardModel() (boardModel string, err error) {
	instance.wg.Wait()

	rsp, err := instance.sendGetRequest(boardModelPath)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	value, err := getValueByPath(boardModelPath, rsp.Value)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	var ok bool

	if instance.boardModel, ok = value.(string); !ok {
		return "", aoserrors.New("wrong boardModel type")
	}

	log.WithField("boardModel ", instance.boardModel).Debug("Get boardModel")

	return instance.boardModel, aoserrors.Wrap(err)
}

// GetSubjects returns the subjects claims.
func (instance *Instance) GetSubjects() (subjects []string, err error) {
	instance.wg.Wait()

	if instance.subjects == nil {
		rsp, err := instance.sendGetRequest(subjectsVISPath)
		if err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = instance.updateSubjects(rsp.Value); err != nil {
			return nil, aoserrors.Wrap(err)
		}
	}

	log.WithField("subjects", instance.subjects).Debug("Get subjects")

	return instance.subjects, aoserrors.Wrap(err)
}

// SubjectsChangedChannel returns subjects changed channel.
func (instance *Instance) SubjectsChangedChannel() (channel <-chan []string) {
	return instance.subjectChangedChannel
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (instance *Instance) handleConnection(url string) {
	for {
		if err := instance.wsClient.Connect(url); err != nil {
			log.Errorf("Can't connect to VIS: %s", err)
			goto reconnect
		}

		instance.subscribeMap = sync.Map{}

		if err := instance.subscribe(subjectsVISPath, instance.handleSubjectsChanged); err != nil {
			log.Errorf("Can't subscribe to VIS: %s", err)
			goto reconnect
		}

		instance.subjects = nil
		instance.vin = ""

		instance.wg.Done()

		{
			err := <-instance.wsClient.ErrorChannel
			log.Errorf("VIS connection errors: %s", err)

			instance.wg.Add(1)
		}

	reconnect:
		if err := instance.wsClient.Disconnect(); err != nil {
			log.Errorf("Can't connect to VIS: %s", err)
		}

		time.Sleep(reconnectTimeout)
	}
}

func (instance *Instance) messageHandler(message []byte) {
	var header visprotocol.MessageHeader

	if err := json.Unmarshal(message, &header); err != nil {
		log.Errorf("Error parsing VIS response: %s", err)
		return
	}

	switch header.Action {
	case visprotocol.ActionSubscription:
		if err := instance.processSubscriptions(message); err != nil {
			log.Errorf("Failed to process subscription: %s", err)
		}

	default:
		log.WithField("action", header.Action).Warning("Unexpected message received")
	}
}

func getValueByPath(path string, value interface{}) (result interface{}, err error) {
	if valueMap, ok := value.(map[string]interface{}); ok {
		if value, ok = valueMap[path]; !ok {
			return nil, aoserrors.New("path not found")
		}

		return value, nil
	}

	if value == nil {
		return result, aoserrors.New("no value found")
	}

	return value, nil
}

func (instance *Instance) processSubscriptions(message []byte) (err error) {
	var notification visprotocol.SubscriptionNotification

	if err = json.Unmarshal(message, &notification); err != nil {
		return aoserrors.Wrap(err)
	}

	// serve subscriptions
	subscriptionFound := false

	instance.subscribeMap.Range(func(key, value interface{}) bool {
		subjectID, ok := key.(string)
		if !ok {
			return true
		}

		if subjectID == notification.SubscriptionID {
			subscriptionFound = true

			if notifyFunc, ok := value.(func(interface{})); ok {
				notifyFunc(notification.Value)

				return false
			}
		}

		return true
	})

	if !subscriptionFound {
		log.Warningf("Unexpected subscription id: %s", notification.SubscriptionID)
	}

	return nil
}

func (instance *Instance) updateSubjects(value interface{}) (err error) {
	instance.Lock()
	defer instance.Unlock()

	value, err = getValueByPath(subjectsVISPath, value)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	itfs, ok := value.([]interface{})
	if !ok {
		return aoserrors.New("wrong subjects type")
	}

	instance.subjects = make([]string, len(itfs))

	for i, itf := range itfs {
		item, ok := itf.(string)
		if !ok {
			return aoserrors.New("wrong subjects type")
		}

		instance.subjects[i] = item
	}

	return nil
}

func (instance *Instance) handleSubjectsChanged(value interface{}) {
	if err := instance.updateSubjects(value); err != nil {
		log.Errorf("Can't set subjects: %s", err)
		return
	}

	log.WithField("subjects", instance.subjects).Debug("subjects changed")

	if len(instance.subjectChangedChannel) == subjectsChangedChannelSize {
		return
	}

	instance.subjectChangedChannel <- instance.subjects
}

func (instance *Instance) subscribe(path string, callback func(value interface{})) (err error) {
	var rsp visprotocol.SubscribeResponse

	req := visprotocol.SubscribeRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionSubscribe,
			RequestID: wsclient.GenerateRequestID(),
		},
		Path: path,
	}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return aoserrors.Wrap(err)
	}

	if rsp.Error != nil {
		return aoserrors.New(rsp.Error.Message)
	}

	if rsp.SubscriptionID == "" {
		return aoserrors.New("no subscriptionID in response")
	}

	instance.subscribeMap.Store(rsp.SubscriptionID, callback)

	return nil
}

func (instance *Instance) sendGetRequest(path string) (rsp visprotocol.GetResponse, err error) {
	req := visprotocol.GetRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionGet,
			RequestID: wsclient.GenerateRequestID(),
		},
		Path: path,
	}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return rsp, aoserrors.Wrap(err)
	}

	return rsp, nil
}
