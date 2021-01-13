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

package visidentifier

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_common/visprotocol"
	"gitpct.epam.com/epmd-aepr/aos_common/wsclient"

	"aos_iamanager/identhandler"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	usersChangedChannelSize = 1
	errorChannelSize        = 1
)

const reconnectTimeout = 10 * time.Second

const (
	vinVISPath     = "Attribute.Vehicle.VehicleIdentification.VIN"
	boardModelPath = "Attribute.BoardIdentification.Model"
	usersVISPath   = "Attribute.Vehicle.UserIdentification.Users"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// Instance vis identifier instance
type Instance struct {
	config instanceConfig

	usersChangedChannel chan []string

	wsClient *wsclient.Client

	vin        string
	boardModel string
	users      []string

	subscribeMap sync.Map

	sync.Mutex
	wg sync.WaitGroup
}

type instanceConfig struct {
	VISServer string `json:"visServer"`
}

/*******************************************************************************
 * init
 ******************************************************************************/

/*******************************************************************************
 * Public
 ******************************************************************************/

// New creates new vis identifier instance
func New(configJSON json.RawMessage) (identifier identhandler.IdentModule, err error) {
	log.Info("Create VIS identification instance")

	instance := &Instance{}

	if err = json.Unmarshal(configJSON, &instance.config); err != nil {
		return nil, err
	}

	if instance.wsClient, err = wsclient.New("VIS", instance.messageHandler); err != nil {
		return nil, err
	}

	instance.usersChangedChannel = make(chan []string, usersChangedChannelSize)

	instance.wg.Add(1)

	go instance.handleConnection(instance.config.VISServer)

	return instance, nil
}

// Close closes vis identifier instance
func (instance *Instance) Close() (err error) {
	log.Info("Close VIS identification instance")

	req := visprotocol.UnsubscribeAllRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionUnsubscribeAll,
			RequestID: wsclient.GenerateRequestID()},
	}

	var rsp visprotocol.UnsubscribeAllResponse

	var retErr error

	if err = instance.wsClient.SendRequest("RequestID", req.RequestID, &req, &rsp); err != nil && retErr == nil {
		retErr = err
	}

	if err = instance.wsClient.Close(); err != nil && retErr == nil {
		retErr = err
	}

	return retErr
}

// GetSystemID returns the system ID
func (instance *Instance) GetSystemID() (systemID string, err error) {
	instance.wg.Wait()

	var rsp visprotocol.GetResponse

	req := visprotocol.GetRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionGet,
			RequestID: wsclient.GenerateRequestID()},
		Path: vinVISPath}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return "", err
	}

	value, err := getValueByPath(vinVISPath, rsp.Value)
	if err != nil {
		return "", err
	}

	ok := false
	if instance.vin, ok = value.(string); !ok {
		return "", errors.New("wrong VIN type")
	}

	log.WithField("VIN", instance.vin).Debug("Get VIN")

	return instance.vin, err
}

// GetBoardModel returns the board model
func (instance *Instance) GetBoardModel() (boardModel string, err error) {
	instance.wg.Wait()

	var rsp visprotocol.GetResponse

	req := visprotocol.GetRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionGet,
			RequestID: wsclient.GenerateRequestID()},
		Path: boardModelPath}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return "", err
	}

	value, err := getValueByPath(boardModelPath, rsp.Value)
	if err != nil {
		return "", err
	}

	ok := false
	if instance.boardModel, ok = value.(string); !ok {
		return "", errors.New("wrong boardModel type")
	}

	log.WithField("boardModel ", instance.boardModel).Debug("Get boardModel")

	return instance.boardModel, err
}

// GetUsers returns the user claims
func (instance *Instance) GetUsers() (users []string, err error) {
	instance.wg.Wait()

	if instance.users == nil {
		var rsp visprotocol.GetResponse

		req := visprotocol.GetRequest{
			MessageHeader: visprotocol.MessageHeader{
				Action:    visprotocol.ActionGet,
				RequestID: wsclient.GenerateRequestID()},
			Path: usersVISPath}

		if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
			return nil, err
		}

		if err = instance.updateUsers(rsp.Value); err != nil {
			return nil, err
		}
	}

	log.WithField("users", instance.users).Debug("Get users")

	return instance.users, err
}

// SetUsers sets the user claims
func (instance *Instance) SetUsers(users []string) (err error) {
	instance.wg.Wait()

	var rsp visprotocol.SetResponse

	req := visprotocol.SetRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionSet,
			RequestID: wsclient.GenerateRequestID()},
		Path:  usersVISPath,
		Value: users,
	}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return err
	}

	return nil
}

// UsersChangedChannel returns users changed channel
func (instance *Instance) UsersChangedChannel() (channel <-chan []string) {
	return instance.usersChangedChannel
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

		if err := instance.subscribe(usersVISPath, instance.handleUsersChanged); err != nil {
			log.Errorf("Can't subscribe to VIS: %s", err)
			goto reconnect
		}

		instance.users = nil
		instance.vin = ""

		instance.wg.Done()

		select {
		case err := <-instance.wsClient.ErrorChannel:
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
		instance.processSubscriptions(message)

	default:
		log.WithField("action", header.Action).Warning("Unexpected message received")
	}
}

func getValueByPath(path string, value interface{}) (result interface{}, err error) {
	if valueMap, ok := value.(map[string]interface{}); ok {
		if value, ok = valueMap[path]; !ok {
			return nil, errors.New("path not found")
		}
		return value, nil
	}

	if value == nil {
		return result, errors.New("no value found")
	}

	return value, nil
}

func (instance *Instance) processSubscriptions(message []byte) (err error) {
	var notification visprotocol.SubscriptionNotification

	if err = json.Unmarshal(message, &notification); err != nil {
		return err
	}

	// serve subscriptions
	subscriptionFound := false
	instance.subscribeMap.Range(func(key, value interface{}) bool {
		if key.(string) == notification.SubscriptionID {
			subscriptionFound = true
			value.(func(interface{}))(notification.Value)
			return false
		}
		return true
	})

	if !subscriptionFound {
		log.Warningf("Unexpected subscription id: %s", notification.SubscriptionID)
	}

	return nil
}

func (instance *Instance) updateUsers(value interface{}) (err error) {
	instance.Lock()
	defer instance.Unlock()

	value, err = getValueByPath(usersVISPath, value)
	if err != nil {
		return err
	}

	itfs, ok := value.([]interface{})
	if !ok {
		return errors.New("wrong users type")
	}

	instance.users = make([]string, len(itfs))

	for i, itf := range itfs {
		item, ok := itf.(string)
		if !ok {
			return errors.New("wrong users type")
		}
		instance.users[i] = item
	}

	return nil
}

func (instance *Instance) handleUsersChanged(value interface{}) {
	if err := instance.updateUsers(value); err != nil {
		log.Errorf("Can't set users: %s", err)
		return
	}

	log.WithField("users", instance.users).Debug("Users changed")

	if len(instance.usersChangedChannel) == usersChangedChannelSize {
		return
	}

	instance.usersChangedChannel <- instance.users
}

func (instance *Instance) subscribe(path string, callback func(value interface{})) (err error) {
	var rsp visprotocol.SubscribeResponse

	req := visprotocol.SubscribeRequest{
		MessageHeader: visprotocol.MessageHeader{
			Action:    visprotocol.ActionSubscribe,
			RequestID: wsclient.GenerateRequestID()},
		Path: path}

	if err = instance.wsClient.SendRequest("RequestID", req.MessageHeader.RequestID, &req, &rsp); err != nil {
		return err
	}

	if rsp.Error != nil {
		return errors.New(rsp.Error.Message)
	}

	if rsp.SubscriptionID == "" {
		return errors.New("no subscriptionID in response")
	}

	instance.subscribeMap.Store(rsp.SubscriptionID, callback)

	return nil
}
