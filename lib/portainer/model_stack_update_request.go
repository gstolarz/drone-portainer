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

// StackUpdateRequest struct for StackUpdateRequest
type StackUpdateRequest struct {
	// New content of the Stack file.
	StackFileContent *string `json:"StackFileContent,omitempty"`
	// A list of environment variables used during stack deployment
	Env *[]StackEnv `json:"Env,omitempty"`
	// Prune services that are no longer referenced (only available for Swarm stacks)
	Prune *bool `json:"Prune,omitempty"`
}

// NewStackUpdateRequest instantiates a new StackUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackUpdateRequest() *StackUpdateRequest {
	this := StackUpdateRequest{}
	return &this
}

// NewStackUpdateRequestWithDefaults instantiates a new StackUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackUpdateRequestWithDefaults() *StackUpdateRequest {
	this := StackUpdateRequest{}
	return &this
}

// GetStackFileContent returns the StackFileContent field value if set, zero value otherwise.
func (o *StackUpdateRequest) GetStackFileContent() string {
	if o == nil || o.StackFileContent == nil {
		var ret string
		return ret
	}
	return *o.StackFileContent
}

// GetStackFileContentOk returns a tuple with the StackFileContent field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackUpdateRequest) GetStackFileContentOk() (*string, bool) {
	if o == nil || o.StackFileContent == nil {
		return nil, false
	}
	return o.StackFileContent, true
}

// HasStackFileContent returns a boolean if a field has been set.
func (o *StackUpdateRequest) HasStackFileContent() bool {
	if o != nil && o.StackFileContent != nil {
		return true
	}

	return false
}

// SetStackFileContent gets a reference to the given string and assigns it to the StackFileContent field.
func (o *StackUpdateRequest) SetStackFileContent(v string) {
	o.StackFileContent = &v
}

// GetEnv returns the Env field value if set, zero value otherwise.
func (o *StackUpdateRequest) GetEnv() []StackEnv {
	if o == nil || o.Env == nil {
		var ret []StackEnv
		return ret
	}
	return *o.Env
}

// GetEnvOk returns a tuple with the Env field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackUpdateRequest) GetEnvOk() (*[]StackEnv, bool) {
	if o == nil || o.Env == nil {
		return nil, false
	}
	return o.Env, true
}

// HasEnv returns a boolean if a field has been set.
func (o *StackUpdateRequest) HasEnv() bool {
	if o != nil && o.Env != nil {
		return true
	}

	return false
}

// SetEnv gets a reference to the given []StackEnv and assigns it to the Env field.
func (o *StackUpdateRequest) SetEnv(v []StackEnv) {
	o.Env = &v
}

// GetPrune returns the Prune field value if set, zero value otherwise.
func (o *StackUpdateRequest) GetPrune() bool {
	if o == nil || o.Prune == nil {
		var ret bool
		return ret
	}
	return *o.Prune
}

// GetPruneOk returns a tuple with the Prune field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackUpdateRequest) GetPruneOk() (*bool, bool) {
	if o == nil || o.Prune == nil {
		return nil, false
	}
	return o.Prune, true
}

// HasPrune returns a boolean if a field has been set.
func (o *StackUpdateRequest) HasPrune() bool {
	if o != nil && o.Prune != nil {
		return true
	}

	return false
}

// SetPrune gets a reference to the given bool and assigns it to the Prune field.
func (o *StackUpdateRequest) SetPrune(v bool) {
	o.Prune = &v
}

func (o StackUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.StackFileContent != nil {
		toSerialize["StackFileContent"] = o.StackFileContent
	}
	if o.Env != nil {
		toSerialize["Env"] = o.Env
	}
	if o.Prune != nil {
		toSerialize["Prune"] = o.Prune
	}
	return json.Marshal(toSerialize)
}

type NullableStackUpdateRequest struct {
	value *StackUpdateRequest
	isSet bool
}

func (v NullableStackUpdateRequest) Get() *StackUpdateRequest {
	return v.value
}

func (v *NullableStackUpdateRequest) Set(val *StackUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableStackUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableStackUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackUpdateRequest(val *StackUpdateRequest) *NullableStackUpdateRequest {
	return &NullableStackUpdateRequest{value: val, isSet: true}
}

func (v NullableStackUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


