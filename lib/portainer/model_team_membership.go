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

// TeamMembership struct for TeamMembership
type TeamMembership struct {
	// Membership identifier
	Id *int32 `json:"Id,omitempty"`
	// User identifier
	UserID *int32 `json:"UserID,omitempty"`
	// Team identifier
	TeamID *int32 `json:"TeamID,omitempty"`
	// Team role (1 for team leader and 2 for team member)
	Role *int32 `json:"Role,omitempty"`
}

// NewTeamMembership instantiates a new TeamMembership object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTeamMembership() *TeamMembership {
	this := TeamMembership{}
	return &this
}

// NewTeamMembershipWithDefaults instantiates a new TeamMembership object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTeamMembershipWithDefaults() *TeamMembership {
	this := TeamMembership{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *TeamMembership) GetId() int32 {
	if o == nil || o.Id == nil {
		var ret int32
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TeamMembership) GetIdOk() (*int32, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *TeamMembership) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given int32 and assigns it to the Id field.
func (o *TeamMembership) SetId(v int32) {
	o.Id = &v
}

// GetUserID returns the UserID field value if set, zero value otherwise.
func (o *TeamMembership) GetUserID() int32 {
	if o == nil || o.UserID == nil {
		var ret int32
		return ret
	}
	return *o.UserID
}

// GetUserIDOk returns a tuple with the UserID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TeamMembership) GetUserIDOk() (*int32, bool) {
	if o == nil || o.UserID == nil {
		return nil, false
	}
	return o.UserID, true
}

// HasUserID returns a boolean if a field has been set.
func (o *TeamMembership) HasUserID() bool {
	if o != nil && o.UserID != nil {
		return true
	}

	return false
}

// SetUserID gets a reference to the given int32 and assigns it to the UserID field.
func (o *TeamMembership) SetUserID(v int32) {
	o.UserID = &v
}

// GetTeamID returns the TeamID field value if set, zero value otherwise.
func (o *TeamMembership) GetTeamID() int32 {
	if o == nil || o.TeamID == nil {
		var ret int32
		return ret
	}
	return *o.TeamID
}

// GetTeamIDOk returns a tuple with the TeamID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TeamMembership) GetTeamIDOk() (*int32, bool) {
	if o == nil || o.TeamID == nil {
		return nil, false
	}
	return o.TeamID, true
}

// HasTeamID returns a boolean if a field has been set.
func (o *TeamMembership) HasTeamID() bool {
	if o != nil && o.TeamID != nil {
		return true
	}

	return false
}

// SetTeamID gets a reference to the given int32 and assigns it to the TeamID field.
func (o *TeamMembership) SetTeamID(v int32) {
	o.TeamID = &v
}

// GetRole returns the Role field value if set, zero value otherwise.
func (o *TeamMembership) GetRole() int32 {
	if o == nil || o.Role == nil {
		var ret int32
		return ret
	}
	return *o.Role
}

// GetRoleOk returns a tuple with the Role field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TeamMembership) GetRoleOk() (*int32, bool) {
	if o == nil || o.Role == nil {
		return nil, false
	}
	return o.Role, true
}

// HasRole returns a boolean if a field has been set.
func (o *TeamMembership) HasRole() bool {
	if o != nil && o.Role != nil {
		return true
	}

	return false
}

// SetRole gets a reference to the given int32 and assigns it to the Role field.
func (o *TeamMembership) SetRole(v int32) {
	o.Role = &v
}

func (o TeamMembership) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["Id"] = o.Id
	}
	if o.UserID != nil {
		toSerialize["UserID"] = o.UserID
	}
	if o.TeamID != nil {
		toSerialize["TeamID"] = o.TeamID
	}
	if o.Role != nil {
		toSerialize["Role"] = o.Role
	}
	return json.Marshal(toSerialize)
}

type NullableTeamMembership struct {
	value *TeamMembership
	isSet bool
}

func (v NullableTeamMembership) Get() *TeamMembership {
	return v.value
}

func (v *NullableTeamMembership) Set(val *TeamMembership) {
	v.value = val
	v.isSet = true
}

func (v NullableTeamMembership) IsSet() bool {
	return v.isSet
}

func (v *NullableTeamMembership) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTeamMembership(val *TeamMembership) *NullableTeamMembership {
	return &NullableTeamMembership{value: val, isSet: true}
}

func (v NullableTeamMembership) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTeamMembership) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


