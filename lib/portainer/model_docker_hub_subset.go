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

// DockerHubSubset struct for DockerHubSubset
type DockerHubSubset struct {
	// Is authentication against DockerHub enabled
	Authentication *bool `json:"Authentication,omitempty"`
	// Username used to authenticate against the DockerHub
	Username *string `json:"Username,omitempty"`
}

// NewDockerHubSubset instantiates a new DockerHubSubset object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDockerHubSubset() *DockerHubSubset {
	this := DockerHubSubset{}
	return &this
}

// NewDockerHubSubsetWithDefaults instantiates a new DockerHubSubset object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDockerHubSubsetWithDefaults() *DockerHubSubset {
	this := DockerHubSubset{}
	return &this
}

// GetAuthentication returns the Authentication field value if set, zero value otherwise.
func (o *DockerHubSubset) GetAuthentication() bool {
	if o == nil || o.Authentication == nil {
		var ret bool
		return ret
	}
	return *o.Authentication
}

// GetAuthenticationOk returns a tuple with the Authentication field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DockerHubSubset) GetAuthenticationOk() (*bool, bool) {
	if o == nil || o.Authentication == nil {
		return nil, false
	}
	return o.Authentication, true
}

// HasAuthentication returns a boolean if a field has been set.
func (o *DockerHubSubset) HasAuthentication() bool {
	if o != nil && o.Authentication != nil {
		return true
	}

	return false
}

// SetAuthentication gets a reference to the given bool and assigns it to the Authentication field.
func (o *DockerHubSubset) SetAuthentication(v bool) {
	o.Authentication = &v
}

// GetUsername returns the Username field value if set, zero value otherwise.
func (o *DockerHubSubset) GetUsername() string {
	if o == nil || o.Username == nil {
		var ret string
		return ret
	}
	return *o.Username
}

// GetUsernameOk returns a tuple with the Username field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DockerHubSubset) GetUsernameOk() (*string, bool) {
	if o == nil || o.Username == nil {
		return nil, false
	}
	return o.Username, true
}

// HasUsername returns a boolean if a field has been set.
func (o *DockerHubSubset) HasUsername() bool {
	if o != nil && o.Username != nil {
		return true
	}

	return false
}

// SetUsername gets a reference to the given string and assigns it to the Username field.
func (o *DockerHubSubset) SetUsername(v string) {
	o.Username = &v
}

func (o DockerHubSubset) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Authentication != nil {
		toSerialize["Authentication"] = o.Authentication
	}
	if o.Username != nil {
		toSerialize["Username"] = o.Username
	}
	return json.Marshal(toSerialize)
}

type NullableDockerHubSubset struct {
	value *DockerHubSubset
	isSet bool
}

func (v NullableDockerHubSubset) Get() *DockerHubSubset {
	return v.value
}

func (v *NullableDockerHubSubset) Set(val *DockerHubSubset) {
	v.value = val
	v.isSet = true
}

func (v NullableDockerHubSubset) IsSet() bool {
	return v.isSet
}

func (v *NullableDockerHubSubset) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDockerHubSubset(val *DockerHubSubset) *NullableDockerHubSubset {
	return &NullableDockerHubSubset{value: val, isSet: true}
}

func (v NullableDockerHubSubset) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDockerHubSubset) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


