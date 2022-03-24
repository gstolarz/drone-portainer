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

// ExtensionCreateRequest struct for ExtensionCreateRequest
type ExtensionCreateRequest struct {
	// License key
	License string `json:"License"`
}

// NewExtensionCreateRequest instantiates a new ExtensionCreateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewExtensionCreateRequest(license string) *ExtensionCreateRequest {
	this := ExtensionCreateRequest{}
	this.License = license
	return &this
}

// NewExtensionCreateRequestWithDefaults instantiates a new ExtensionCreateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewExtensionCreateRequestWithDefaults() *ExtensionCreateRequest {
	this := ExtensionCreateRequest{}
	return &this
}

// GetLicense returns the License field value
func (o *ExtensionCreateRequest) GetLicense() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.License
}

// GetLicenseOk returns a tuple with the License field value
// and a boolean to check if the value has been set.
func (o *ExtensionCreateRequest) GetLicenseOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.License, true
}

// SetLicense sets field value
func (o *ExtensionCreateRequest) SetLicense(v string) {
	o.License = v
}

func (o ExtensionCreateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["License"] = o.License
	}
	return json.Marshal(toSerialize)
}

type NullableExtensionCreateRequest struct {
	value *ExtensionCreateRequest
	isSet bool
}

func (v NullableExtensionCreateRequest) Get() *ExtensionCreateRequest {
	return v.value
}

func (v *NullableExtensionCreateRequest) Set(val *ExtensionCreateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableExtensionCreateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableExtensionCreateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableExtensionCreateRequest(val *ExtensionCreateRequest) *NullableExtensionCreateRequest {
	return &NullableExtensionCreateRequest{value: val, isSet: true}
}

func (v NullableExtensionCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableExtensionCreateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

