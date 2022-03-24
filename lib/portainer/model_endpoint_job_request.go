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

// EndpointJobRequest struct for EndpointJobRequest
type EndpointJobRequest struct {
	// Container image which will be used to execute the job
	Image string `json:"Image"`
	// Content of the job script
	FileContent string `json:"FileContent"`
}

// NewEndpointJobRequest instantiates a new EndpointJobRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEndpointJobRequest(image string, fileContent string) *EndpointJobRequest {
	this := EndpointJobRequest{}
	this.Image = image
	this.FileContent = fileContent
	return &this
}

// NewEndpointJobRequestWithDefaults instantiates a new EndpointJobRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEndpointJobRequestWithDefaults() *EndpointJobRequest {
	this := EndpointJobRequest{}
	return &this
}

// GetImage returns the Image field value
func (o *EndpointJobRequest) GetImage() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Image
}

// GetImageOk returns a tuple with the Image field value
// and a boolean to check if the value has been set.
func (o *EndpointJobRequest) GetImageOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Image, true
}

// SetImage sets field value
func (o *EndpointJobRequest) SetImage(v string) {
	o.Image = v
}

// GetFileContent returns the FileContent field value
func (o *EndpointJobRequest) GetFileContent() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FileContent
}

// GetFileContentOk returns a tuple with the FileContent field value
// and a boolean to check if the value has been set.
func (o *EndpointJobRequest) GetFileContentOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.FileContent, true
}

// SetFileContent sets field value
func (o *EndpointJobRequest) SetFileContent(v string) {
	o.FileContent = v
}

func (o EndpointJobRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["Image"] = o.Image
	}
	if true {
		toSerialize["FileContent"] = o.FileContent
	}
	return json.Marshal(toSerialize)
}

type NullableEndpointJobRequest struct {
	value *EndpointJobRequest
	isSet bool
}

func (v NullableEndpointJobRequest) Get() *EndpointJobRequest {
	return v.value
}

func (v *NullableEndpointJobRequest) Set(val *EndpointJobRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableEndpointJobRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableEndpointJobRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEndpointJobRequest(val *EndpointJobRequest) *NullableEndpointJobRequest {
	return &NullableEndpointJobRequest{value: val, isSet: true}
}

func (v NullableEndpointJobRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEndpointJobRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

