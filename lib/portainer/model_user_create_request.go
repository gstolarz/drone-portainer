/*
 * Portainer API
 *
 * Portainer API is an HTTP API served by Portainer. It is used by the Portainer UI and everything you can do with the UI can be done using the HTTP API. Examples are available at https://gist.github.com/deviantony/77026d402366b4b43fa5918d41bc42f8 You can find out more about Portainer at [http://portainer.io](http://portainer.io) and get some support on [Slack](http://portainer.io/slack/).  # Authentication  Most of the API endpoints require to be authenticated as well as some level of authorization to be used. Portainer API uses JSON Web Token to manage authentication and thus requires you to provide a token in the **Authorization** header of each request with the **Bearer** authentication mechanism.  Example: ``` Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOjEsImV4cCI6MTQ5OTM3NjE1NH0.NJ6vE8FY1WG6jsRQzfMqeatJ4vh2TWAeeYfDhP71YEE ```  # Security  Each API endpoint has an associated access policy, it is documented in the description of each endpoint.  Different access policies are available: * Public access * Authenticated access * Restricted access * Administrator access  ### Public access  No authentication is required to access the endpoints with this access policy.  ### Authenticated access  Authentication is required to access the endpoints with this access policy.  ### Restricted access  Authentication is required to access the endpoints with this access policy. Extra-checks might be added to ensure access to the resource is granted. Returned data might also be filtered.  ### Administrator access  Authentication as well as an administrator role are required to access the endpoints with this access policy.  # Execute Docker requests  Portainer **DO NOT** expose specific endpoints to manage your Docker resources (create a container, remove a volume, etc...).  Instead, it acts as a reverse-proxy to the Docker HTTP API. This means that you can execute Docker requests **via** the Portainer HTTP API.  To do so, you can use the `/endpoints/{id}/docker` Portainer API endpoint (which is not documented below due to Swagger limitations). This endpoint has a restricted access policy so you still need to be authenticated to be able to query this endpoint. Any query on this endpoint will be proxied to the Docker API of the associated endpoint (requests and responses objects are the same as documented in the Docker API).  **NOTE**: You can find more information on how to query the Docker API in the [Docker official documentation](https://docs.docker.com/engine/api/v1.30/) as well as in [this Portainer example](https://gist.github.com/deviantony/77026d402366b4b43fa5918d41bc42f8). 
 *
 * API version: 1.24.1
 * Contact: info@portainer.io
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package portainer

import (
	"encoding/json"
)

// UserCreateRequest struct for UserCreateRequest
type UserCreateRequest struct {
	// Username
	Username string `json:"Username"`
	// Password
	Password string `json:"Password"`
	// User role (1 for administrator account and 2 for regular account)
	Role int32 `json:"Role"`
}

// NewUserCreateRequest instantiates a new UserCreateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserCreateRequest(username string, password string, role int32) *UserCreateRequest {
	this := UserCreateRequest{}
	this.Username = username
	this.Password = password
	this.Role = role
	return &this
}

// NewUserCreateRequestWithDefaults instantiates a new UserCreateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserCreateRequestWithDefaults() *UserCreateRequest {
	this := UserCreateRequest{}
	return &this
}

// GetUsername returns the Username field value
func (o *UserCreateRequest) GetUsername() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Username
}

// GetUsernameOk returns a tuple with the Username field value
// and a boolean to check if the value has been set.
func (o *UserCreateRequest) GetUsernameOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Username, true
}

// SetUsername sets field value
func (o *UserCreateRequest) SetUsername(v string) {
	o.Username = v
}

// GetPassword returns the Password field value
func (o *UserCreateRequest) GetPassword() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Password
}

// GetPasswordOk returns a tuple with the Password field value
// and a boolean to check if the value has been set.
func (o *UserCreateRequest) GetPasswordOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Password, true
}

// SetPassword sets field value
func (o *UserCreateRequest) SetPassword(v string) {
	o.Password = v
}

// GetRole returns the Role field value
func (o *UserCreateRequest) GetRole() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Role
}

// GetRoleOk returns a tuple with the Role field value
// and a boolean to check if the value has been set.
func (o *UserCreateRequest) GetRoleOk() (*int32, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Role, true
}

// SetRole sets field value
func (o *UserCreateRequest) SetRole(v int32) {
	o.Role = v
}

func (o UserCreateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["Username"] = o.Username
	}
	if true {
		toSerialize["Password"] = o.Password
	}
	if true {
		toSerialize["Role"] = o.Role
	}
	return json.Marshal(toSerialize)
}

type NullableUserCreateRequest struct {
	value *UserCreateRequest
	isSet bool
}

func (v NullableUserCreateRequest) Get() *UserCreateRequest {
	return v.value
}

func (v *NullableUserCreateRequest) Set(val *UserCreateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableUserCreateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableUserCreateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserCreateRequest(val *UserCreateRequest) *NullableUserCreateRequest {
	return &NullableUserCreateRequest{value: val, isSet: true}
}

func (v NullableUserCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserCreateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


