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

// TeamMembershipUpdateRequest struct for TeamMembershipUpdateRequest
type TeamMembershipUpdateRequest struct {
	// User identifier
	UserID int32 `json:"UserID"`
	// Team identifier
	TeamID int32 `json:"TeamID"`
	// Role for the user inside the team (1 for leader and 2 for regular member)
	Role int32 `json:"Role"`
}

// NewTeamMembershipUpdateRequest instantiates a new TeamMembershipUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTeamMembershipUpdateRequest(userID int32, teamID int32, role int32) *TeamMembershipUpdateRequest {
	this := TeamMembershipUpdateRequest{}
	this.UserID = userID
	this.TeamID = teamID
	this.Role = role
	return &this
}

// NewTeamMembershipUpdateRequestWithDefaults instantiates a new TeamMembershipUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTeamMembershipUpdateRequestWithDefaults() *TeamMembershipUpdateRequest {
	this := TeamMembershipUpdateRequest{}
	return &this
}

// GetUserID returns the UserID field value
func (o *TeamMembershipUpdateRequest) GetUserID() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.UserID
}

// GetUserIDOk returns a tuple with the UserID field value
// and a boolean to check if the value has been set.
func (o *TeamMembershipUpdateRequest) GetUserIDOk() (*int32, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.UserID, true
}

// SetUserID sets field value
func (o *TeamMembershipUpdateRequest) SetUserID(v int32) {
	o.UserID = v
}

// GetTeamID returns the TeamID field value
func (o *TeamMembershipUpdateRequest) GetTeamID() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.TeamID
}

// GetTeamIDOk returns a tuple with the TeamID field value
// and a boolean to check if the value has been set.
func (o *TeamMembershipUpdateRequest) GetTeamIDOk() (*int32, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.TeamID, true
}

// SetTeamID sets field value
func (o *TeamMembershipUpdateRequest) SetTeamID(v int32) {
	o.TeamID = v
}

// GetRole returns the Role field value
func (o *TeamMembershipUpdateRequest) GetRole() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Role
}

// GetRoleOk returns a tuple with the Role field value
// and a boolean to check if the value has been set.
func (o *TeamMembershipUpdateRequest) GetRoleOk() (*int32, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Role, true
}

// SetRole sets field value
func (o *TeamMembershipUpdateRequest) SetRole(v int32) {
	o.Role = v
}

func (o TeamMembershipUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["UserID"] = o.UserID
	}
	if true {
		toSerialize["TeamID"] = o.TeamID
	}
	if true {
		toSerialize["Role"] = o.Role
	}
	return json.Marshal(toSerialize)
}

type NullableTeamMembershipUpdateRequest struct {
	value *TeamMembershipUpdateRequest
	isSet bool
}

func (v NullableTeamMembershipUpdateRequest) Get() *TeamMembershipUpdateRequest {
	return v.value
}

func (v *NullableTeamMembershipUpdateRequest) Set(val *TeamMembershipUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableTeamMembershipUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableTeamMembershipUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTeamMembershipUpdateRequest(val *TeamMembershipUpdateRequest) *NullableTeamMembershipUpdateRequest {
	return &NullableTeamMembershipUpdateRequest{value: val, isSet: true}
}

func (v NullableTeamMembershipUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTeamMembershipUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


