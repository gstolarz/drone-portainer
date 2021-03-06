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

// EndpointGroupCreateRequest struct for EndpointGroupCreateRequest
type EndpointGroupCreateRequest struct {
	// Endpoint group name
	Name string `json:"Name"`
	// Endpoint group description
	Description *string `json:"Description,omitempty"`
	Labels *[]Pair `json:"Labels,omitempty"`
	// List of endpoint identifiers that will be part of this group
	AssociatedEndpoints *[]int32 `json:"AssociatedEndpoints,omitempty"`
}

// NewEndpointGroupCreateRequest instantiates a new EndpointGroupCreateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEndpointGroupCreateRequest(name string) *EndpointGroupCreateRequest {
	this := EndpointGroupCreateRequest{}
	this.Name = name
	return &this
}

// NewEndpointGroupCreateRequestWithDefaults instantiates a new EndpointGroupCreateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEndpointGroupCreateRequestWithDefaults() *EndpointGroupCreateRequest {
	this := EndpointGroupCreateRequest{}
	return &this
}

// GetName returns the Name field value
func (o *EndpointGroupCreateRequest) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *EndpointGroupCreateRequest) GetNameOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *EndpointGroupCreateRequest) SetName(v string) {
	o.Name = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *EndpointGroupCreateRequest) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointGroupCreateRequest) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *EndpointGroupCreateRequest) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *EndpointGroupCreateRequest) SetDescription(v string) {
	o.Description = &v
}

// GetLabels returns the Labels field value if set, zero value otherwise.
func (o *EndpointGroupCreateRequest) GetLabels() []Pair {
	if o == nil || o.Labels == nil {
		var ret []Pair
		return ret
	}
	return *o.Labels
}

// GetLabelsOk returns a tuple with the Labels field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointGroupCreateRequest) GetLabelsOk() (*[]Pair, bool) {
	if o == nil || o.Labels == nil {
		return nil, false
	}
	return o.Labels, true
}

// HasLabels returns a boolean if a field has been set.
func (o *EndpointGroupCreateRequest) HasLabels() bool {
	if o != nil && o.Labels != nil {
		return true
	}

	return false
}

// SetLabels gets a reference to the given []Pair and assigns it to the Labels field.
func (o *EndpointGroupCreateRequest) SetLabels(v []Pair) {
	o.Labels = &v
}

// GetAssociatedEndpoints returns the AssociatedEndpoints field value if set, zero value otherwise.
func (o *EndpointGroupCreateRequest) GetAssociatedEndpoints() []int32 {
	if o == nil || o.AssociatedEndpoints == nil {
		var ret []int32
		return ret
	}
	return *o.AssociatedEndpoints
}

// GetAssociatedEndpointsOk returns a tuple with the AssociatedEndpoints field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointGroupCreateRequest) GetAssociatedEndpointsOk() (*[]int32, bool) {
	if o == nil || o.AssociatedEndpoints == nil {
		return nil, false
	}
	return o.AssociatedEndpoints, true
}

// HasAssociatedEndpoints returns a boolean if a field has been set.
func (o *EndpointGroupCreateRequest) HasAssociatedEndpoints() bool {
	if o != nil && o.AssociatedEndpoints != nil {
		return true
	}

	return false
}

// SetAssociatedEndpoints gets a reference to the given []int32 and assigns it to the AssociatedEndpoints field.
func (o *EndpointGroupCreateRequest) SetAssociatedEndpoints(v []int32) {
	o.AssociatedEndpoints = &v
}

func (o EndpointGroupCreateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["Name"] = o.Name
	}
	if o.Description != nil {
		toSerialize["Description"] = o.Description
	}
	if o.Labels != nil {
		toSerialize["Labels"] = o.Labels
	}
	if o.AssociatedEndpoints != nil {
		toSerialize["AssociatedEndpoints"] = o.AssociatedEndpoints
	}
	return json.Marshal(toSerialize)
}

type NullableEndpointGroupCreateRequest struct {
	value *EndpointGroupCreateRequest
	isSet bool
}

func (v NullableEndpointGroupCreateRequest) Get() *EndpointGroupCreateRequest {
	return v.value
}

func (v *NullableEndpointGroupCreateRequest) Set(val *EndpointGroupCreateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableEndpointGroupCreateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableEndpointGroupCreateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEndpointGroupCreateRequest(val *EndpointGroupCreateRequest) *NullableEndpointGroupCreateRequest {
	return &NullableEndpointGroupCreateRequest{value: val, isSet: true}
}

func (v NullableEndpointGroupCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEndpointGroupCreateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


