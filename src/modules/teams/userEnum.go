package teams

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
)

// URL_PRESENCE_TEAMS is the URL the get additional information on a user
var URL_PRESENCE_TEAMS = "https://presence.teams.microsoft.com/v1/presence/getpresence/"

// URL_TEAMS is the URL to search username addresses
var URL_TEAMS = "https://teams.microsoft.com/api/mt/emea/beta/users/%s/externalsearchv3"

// CLIENT_VERSION is the header which is sent for API requests
var CLIENT_VERSION = "27/1.0.0.2021011237"

func UserEnum(optionsInterface *interface{}, username string, threadindex int) (bool, int) {

	options := (*optionsInterface).(*Options)
	var valid = false
	url := fmt.Sprintf(URL_TEAMS, username)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", options.Token)
	req.Header.Add("x-ms-client-version", CLIENT_VERSION)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           options.ProxyHTTP,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		options.Log.Error("Error on response.\n[ERRO] - " + err.Error())
	}

	body, _ := ioutil.ReadAll(resp.Body)

	var jsonInterface interface{}
	var usefulInformation []struct {
		DisplayName string `json:"displayName"`
		Mri         string `json:"mri"`
	}

	json.Unmarshal([]byte(body), &jsonInterface)
	json.Unmarshal([]byte(body), &usefulInformation)

	options.Log.Debug("Status code: " + strconv.Itoa(resp.StatusCode))

	bytes, _ := json.MarshalIndent(jsonInterface, "", " ")
	options.Log.Debug("Response: " + string(bytes))

	switch resp.StatusCode {
	case 200:
		if reflect.ValueOf(jsonInterface).Len() > 0 {
			presence, device, outOfOfficeNote := options.getPresence(usefulInformation[0].Mri, options.Token, options.Log)
			options.Log.Success(username + " - " + usefulInformation[0].DisplayName + " - " + presence + " - " + device + " - " + outOfOfficeNote)
			valid = true
		} else {
			options.Log.Fail(username)
		}
		// If the status code is 403 it means the user exists but the organization did not enable connection from outside
	case 403:
		options.Log.Success(username)
		valid = true
	case 401:
		options.Log.Fail(username)
		options.Log.Info("The token may be invalid or expired. The status code returned by the server is 401")
	default:
		options.Log.Fail(username)
		options.Log.Error("Something went wrong. The status code returned by the server is " + strconv.Itoa(resp.StatusCode))
	}
	return valid, 0
}
