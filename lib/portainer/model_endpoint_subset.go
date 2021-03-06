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

// EndpointSubset struct for EndpointSubset
type EndpointSubset struct {
	// Endpoint identifier
	Id *int32 `json:"Id,omitempty"`
	// Endpoint name
	Name *string `json:"Name,omitempty"`
	// Endpoint environment type. 1 for a Docker environment, 2 for an agent on Docker environment, 3 for an Azure environment.
	Type *int32 `json:"Type,omitempty"`
	// URL or IP address of the Docker host associated to this endpoint
	URL *string `json:"URL,omitempty"`
	// URL or IP address where exposed containers will be reachable
	PublicURL *string `json:"PublicURL,omitempty"`
	// Endpoint group identifier
	GroupID *int32 `json:"GroupID,omitempty"`
	// List of user identifiers authorized to connect to this endpoint
	AuthorizedUsers *[]int32 `json:"AuthorizedUsers,omitempty"`
	// List of team identifiers authorized to connect to this endpoint
	AuthorizedTeams *[]int32 `json:"AuthorizedTeams,omitempty"`
	TLSConfig *TLSConfiguration `json:"TLSConfig,omitempty"`
}

// NewEndpointSubset instantiates a new EndpointSubset object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEndpointSubset() *EndpointSubset {
	this := EndpointSubset{}
	return &this
}

// NewEndpointSubsetWithDefaults instantiates a new EndpointSubset object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEndpointSubsetWithDefaults() *EndpointSubset {
	this := EndpointSubset{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *EndpointSubset) GetId() int32 {
	if o == nil || o.Id == nil {
		var ret int32
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetIdOk() (*int32, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *EndpointSubset) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given int32 and assigns it to the Id field.
func (o *EndpointSubset) SetId(v int32) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *EndpointSubset) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *EndpointSubset) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *EndpointSubset) SetName(v string) {
	o.Name = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *EndpointSubset) GetType() int32 {
	if o == nil || o.Type == nil {
		var ret int32
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetTypeOk() (*int32, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *EndpointSubset) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given int32 and assigns it to the Type field.
func (o *EndpointSubset) SetType(v int32) {
	o.Type = &v
}

// GetURL returns the URL field value if set, zero value otherwise.
func (o *EndpointSubset) GetURL() string {
	if o == nil || o.URL == nil {
		var ret string
		return ret
	}
	return *o.URL
}

// GetURLOk returns a tuple with the URL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetURLOk() (*string, bool) {
	if o == nil || o.URL == nil {
		return nil, false
	}
	return o.URL, true
}

// HasURL returns a boolean if a field has been set.
func (o *EndpointSubset) HasURL() bool {
	if o != nil && o.URL != nil {
		return true
	}

	return false
}

// SetURL gets a reference to the given string and assigns it to the URL field.
func (o *EndpointSubset) SetURL(v string) {
	o.URL = &v
}

// GetPublicURL returns the PublicURL field value if set, zero value otherwise.
func (o *EndpointSubset) GetPublicURL() string {
	if o == nil || o.PublicURL == nil {
		var ret string
		return ret
	}
	return *o.PublicURL
}

// GetPublicURLOk returns a tuple with the PublicURL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetPublicURLOk() (*string, bool) {
	if o == nil || o.PublicURL == nil {
		return nil, false
	}
	return o.PublicURL, true
}

// HasPublicURL returns a boolean if a field has been set.
func (o *EndpointSubset) HasPublicURL() bool {
	if o != nil && o.PublicURL != nil {
		return true
	}

	return false
}

// SetPublicURL gets a reference to the given string and assigns it to the PublicURL field.
func (o *EndpointSubset) SetPublicURL(v string) {
	o.PublicURL = &v
}

// GetGroupID returns the GroupID field value if set, zero value otherwise.
func (o *EndpointSubset) GetGroupID() int32 {
	if o == nil || o.GroupID == nil {
		var ret int32
		return ret
	}
	return *o.GroupID
}

// GetGroupIDOk returns a tuple with the GroupID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetGroupIDOk() (*int32, bool) {
	if o == nil || o.GroupID == nil {
		return nil, false
	}
	return o.GroupID, true
}

// HasGroupID returns a boolean if a field has been set.
func (o *EndpointSubset) HasGroupID() bool {
	if o != nil && o.GroupID != nil {
		return true
	}

	return false
}

// SetGroupID gets a reference to the given int32 and assigns it to the GroupID field.
func (o *EndpointSubset) SetGroupID(v int32) {
	o.GroupID = &v
}

// GetAuthorizedUsers returns the AuthorizedUsers field value if set, zero value otherwise.
func (o *EndpointSubset) GetAuthorizedUsers() []int32 {
	if o == nil || o.AuthorizedUsers == nil {
		var ret []int32
		return ret
	}
	return *o.AuthorizedUsers
}

// GetAuthorizedUsersOk returns a tuple with the AuthorizedUsers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetAuthorizedUsersOk() (*[]int32, bool) {
	if o == nil || o.AuthorizedUsers == nil {
		return nil, false
	}
	return o.AuthorizedUsers, true
}

// HasAuthorizedUsers returns a boolean if a field has been set.
func (o *EndpointSubset) HasAuthorizedUsers() bool {
	if o != nil && o.AuthorizedUsers != nil {
		return true
	}

	return false
}

// SetAuthorizedUsers gets a reference to the given []int32 and assigns it to the AuthorizedUsers field.
func (o *EndpointSubset) SetAuthorizedUsers(v []int32) {
	o.AuthorizedUsers = &v
}

// GetAuthorizedTeams returns the AuthorizedTeams field value if set, zero value otherwise.
func (o *EndpointSubset) GetAuthorizedTeams() []int32 {
	if o == nil || o.AuthorizedTeams == nil {
		var ret []int32
		return ret
	}
	return *o.AuthorizedTeams
}

// GetAuthorizedTeamsOk returns a tuple with the AuthorizedTeams field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetAuthorizedTeamsOk() (*[]int32, bool) {
	if o == nil || o.AuthorizedTeams == nil {
		return nil, false
	}
	return o.AuthorizedTeams, true
}

// HasAuthorizedTeams returns a boolean if a field has been set.
func (o *EndpointSubset) HasAuthorizedTeams() bool {
	if o != nil && o.AuthorizedTeams != nil {
		return true
	}

	return false
}

// SetAuthorizedTeams gets a reference to the given []int32 and assigns it to the AuthorizedTeams field.
func (o *EndpointSubset) SetAuthorizedTeams(v []int32) {
	o.AuthorizedTeams = &v
}

// GetTLSConfig returns the TLSConfig field value if set, zero value otherwise.
func (o *EndpointSubset) GetTLSConfig() TLSConfiguration {
	if o == nil || o.TLSConfig == nil {
		var ret TLSConfiguration
		return ret
	}
	return *o.TLSConfig
}

// GetTLSConfigOk returns a tuple with the TLSConfig field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndpointSubset) GetTLSConfigOk() (*TLSConfiguration, bool) {
	if o == nil || o.TLSConfig == nil {
		return nil, false
	}
	return o.TLSConfig, true
}

// HasTLSConfig returns a boolean if a field has been set.
func (o *EndpointSubset) HasTLSConfig() bool {
	if o != nil && o.TLSConfig != nil {
		return true
	}

	return false
}

// SetTLSConfig gets a reference to the given TLSConfiguration and assigns it to the TLSConfig field.
func (o *EndpointSubset) SetTLSConfig(v TLSConfiguration) {
	o.TLSConfig = &v
}

func (o EndpointSubset) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["Id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["Name"] = o.Name
	}
	if o.Type != nil {
		toSerialize["Type"] = o.Type
	}
	if o.URL != nil {
		toSerialize["URL"] = o.URL
	}
	if o.PublicURL != nil {
		toSerialize["PublicURL"] = o.PublicURL
	}
	if o.GroupID != nil {
		toSerialize["GroupID"] = o.GroupID
	}
	if o.AuthorizedUsers != nil {
		toSerialize["AuthorizedUsers"] = o.AuthorizedUsers
	}
	if o.AuthorizedTeams != nil {
		toSerialize["AuthorizedTeams"] = o.AuthorizedTeams
	}
	if o.TLSConfig != nil {
		toSerialize["TLSConfig"] = o.TLSConfig
	}
	return json.Marshal(toSerialize)
}

type NullableEndpointSubset struct {
	value *EndpointSubset
	isSet bool
}

func (v NullableEndpointSubset) Get() *EndpointSubset {
	return v.value
}

func (v *NullableEndpointSubset) Set(val *EndpointSubset) {
	v.value = val
	v.isSet = true
}

func (v NullableEndpointSubset) IsSet() bool {
	return v.isSet
}

func (v *NullableEndpointSubset) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEndpointSubset(val *EndpointSubset) *NullableEndpointSubset {
	return &NullableEndpointSubset{value: val, isSet: true}
}

func (v NullableEndpointSubset) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEndpointSubset) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


