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

// PublicSettingsInspectResponse struct for PublicSettingsInspectResponse
type PublicSettingsInspectResponse struct {
	// URL to a logo that will be displayed on the login page as well as on top of the sidebar. Will use default Portainer logo when value is empty string
	LogoURL *string `json:"LogoURL,omitempty"`
	// Whether to display or not external templates contributions as sub-menus in the UI.
	DisplayExternalContributors *bool `json:"DisplayExternalContributors,omitempty"`
	// Active authentication method for the Portainer instance. Valid values are: 1 for managed or 2 for LDAP.
	AuthenticationMethod *int32 `json:"AuthenticationMethod,omitempty"`
	// Whether non-administrator should be able to use bind mounts when creating containers
	AllowBindMountsForRegularUsers *bool `json:"AllowBindMountsForRegularUsers,omitempty"`
	// Whether non-administrator should be able to use privileged mode when creating containers
	AllowPrivilegedModeForRegularUsers *bool `json:"AllowPrivilegedModeForRegularUsers,omitempty"`
}

// NewPublicSettingsInspectResponse instantiates a new PublicSettingsInspectResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPublicSettingsInspectResponse() *PublicSettingsInspectResponse {
	this := PublicSettingsInspectResponse{}
	return &this
}

// NewPublicSettingsInspectResponseWithDefaults instantiates a new PublicSettingsInspectResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPublicSettingsInspectResponseWithDefaults() *PublicSettingsInspectResponse {
	this := PublicSettingsInspectResponse{}
	return &this
}

// GetLogoURL returns the LogoURL field value if set, zero value otherwise.
func (o *PublicSettingsInspectResponse) GetLogoURL() string {
	if o == nil || o.LogoURL == nil {
		var ret string
		return ret
	}
	return *o.LogoURL
}

// GetLogoURLOk returns a tuple with the LogoURL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicSettingsInspectResponse) GetLogoURLOk() (*string, bool) {
	if o == nil || o.LogoURL == nil {
		return nil, false
	}
	return o.LogoURL, true
}

// HasLogoURL returns a boolean if a field has been set.
func (o *PublicSettingsInspectResponse) HasLogoURL() bool {
	if o != nil && o.LogoURL != nil {
		return true
	}

	return false
}

// SetLogoURL gets a reference to the given string and assigns it to the LogoURL field.
func (o *PublicSettingsInspectResponse) SetLogoURL(v string) {
	o.LogoURL = &v
}

// GetDisplayExternalContributors returns the DisplayExternalContributors field value if set, zero value otherwise.
func (o *PublicSettingsInspectResponse) GetDisplayExternalContributors() bool {
	if o == nil || o.DisplayExternalContributors == nil {
		var ret bool
		return ret
	}
	return *o.DisplayExternalContributors
}

// GetDisplayExternalContributorsOk returns a tuple with the DisplayExternalContributors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicSettingsInspectResponse) GetDisplayExternalContributorsOk() (*bool, bool) {
	if o == nil || o.DisplayExternalContributors == nil {
		return nil, false
	}
	return o.DisplayExternalContributors, true
}

// HasDisplayExternalContributors returns a boolean if a field has been set.
func (o *PublicSettingsInspectResponse) HasDisplayExternalContributors() bool {
	if o != nil && o.DisplayExternalContributors != nil {
		return true
	}

	return false
}

// SetDisplayExternalContributors gets a reference to the given bool and assigns it to the DisplayExternalContributors field.
func (o *PublicSettingsInspectResponse) SetDisplayExternalContributors(v bool) {
	o.DisplayExternalContributors = &v
}

// GetAuthenticationMethod returns the AuthenticationMethod field value if set, zero value otherwise.
func (o *PublicSettingsInspectResponse) GetAuthenticationMethod() int32 {
	if o == nil || o.AuthenticationMethod == nil {
		var ret int32
		return ret
	}
	return *o.AuthenticationMethod
}

// GetAuthenticationMethodOk returns a tuple with the AuthenticationMethod field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicSettingsInspectResponse) GetAuthenticationMethodOk() (*int32, bool) {
	if o == nil || o.AuthenticationMethod == nil {
		return nil, false
	}
	return o.AuthenticationMethod, true
}

// HasAuthenticationMethod returns a boolean if a field has been set.
func (o *PublicSettingsInspectResponse) HasAuthenticationMethod() bool {
	if o != nil && o.AuthenticationMethod != nil {
		return true
	}

	return false
}

// SetAuthenticationMethod gets a reference to the given int32 and assigns it to the AuthenticationMethod field.
func (o *PublicSettingsInspectResponse) SetAuthenticationMethod(v int32) {
	o.AuthenticationMethod = &v
}

// GetAllowBindMountsForRegularUsers returns the AllowBindMountsForRegularUsers field value if set, zero value otherwise.
func (o *PublicSettingsInspectResponse) GetAllowBindMountsForRegularUsers() bool {
	if o == nil || o.AllowBindMountsForRegularUsers == nil {
		var ret bool
		return ret
	}
	return *o.AllowBindMountsForRegularUsers
}

// GetAllowBindMountsForRegularUsersOk returns a tuple with the AllowBindMountsForRegularUsers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicSettingsInspectResponse) GetAllowBindMountsForRegularUsersOk() (*bool, bool) {
	if o == nil || o.AllowBindMountsForRegularUsers == nil {
		return nil, false
	}
	return o.AllowBindMountsForRegularUsers, true
}

// HasAllowBindMountsForRegularUsers returns a boolean if a field has been set.
func (o *PublicSettingsInspectResponse) HasAllowBindMountsForRegularUsers() bool {
	if o != nil && o.AllowBindMountsForRegularUsers != nil {
		return true
	}

	return false
}

// SetAllowBindMountsForRegularUsers gets a reference to the given bool and assigns it to the AllowBindMountsForRegularUsers field.
func (o *PublicSettingsInspectResponse) SetAllowBindMountsForRegularUsers(v bool) {
	o.AllowBindMountsForRegularUsers = &v
}

// GetAllowPrivilegedModeForRegularUsers returns the AllowPrivilegedModeForRegularUsers field value if set, zero value otherwise.
func (o *PublicSettingsInspectResponse) GetAllowPrivilegedModeForRegularUsers() bool {
	if o == nil || o.AllowPrivilegedModeForRegularUsers == nil {
		var ret bool
		return ret
	}
	return *o.AllowPrivilegedModeForRegularUsers
}

// GetAllowPrivilegedModeForRegularUsersOk returns a tuple with the AllowPrivilegedModeForRegularUsers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicSettingsInspectResponse) GetAllowPrivilegedModeForRegularUsersOk() (*bool, bool) {
	if o == nil || o.AllowPrivilegedModeForRegularUsers == nil {
		return nil, false
	}
	return o.AllowPrivilegedModeForRegularUsers, true
}

// HasAllowPrivilegedModeForRegularUsers returns a boolean if a field has been set.
func (o *PublicSettingsInspectResponse) HasAllowPrivilegedModeForRegularUsers() bool {
	if o != nil && o.AllowPrivilegedModeForRegularUsers != nil {
		return true
	}

	return false
}

// SetAllowPrivilegedModeForRegularUsers gets a reference to the given bool and assigns it to the AllowPrivilegedModeForRegularUsers field.
func (o *PublicSettingsInspectResponse) SetAllowPrivilegedModeForRegularUsers(v bool) {
	o.AllowPrivilegedModeForRegularUsers = &v
}

func (o PublicSettingsInspectResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.LogoURL != nil {
		toSerialize["LogoURL"] = o.LogoURL
	}
	if o.DisplayExternalContributors != nil {
		toSerialize["DisplayExternalContributors"] = o.DisplayExternalContributors
	}
	if o.AuthenticationMethod != nil {
		toSerialize["AuthenticationMethod"] = o.AuthenticationMethod
	}
	if o.AllowBindMountsForRegularUsers != nil {
		toSerialize["AllowBindMountsForRegularUsers"] = o.AllowBindMountsForRegularUsers
	}
	if o.AllowPrivilegedModeForRegularUsers != nil {
		toSerialize["AllowPrivilegedModeForRegularUsers"] = o.AllowPrivilegedModeForRegularUsers
	}
	return json.Marshal(toSerialize)
}

type NullablePublicSettingsInspectResponse struct {
	value *PublicSettingsInspectResponse
	isSet bool
}

func (v NullablePublicSettingsInspectResponse) Get() *PublicSettingsInspectResponse {
	return v.value
}

func (v *NullablePublicSettingsInspectResponse) Set(val *PublicSettingsInspectResponse) {
	v.value = val
	v.isSet = true
}

func (v NullablePublicSettingsInspectResponse) IsSet() bool {
	return v.isSet
}

func (v *NullablePublicSettingsInspectResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePublicSettingsInspectResponse(val *PublicSettingsInspectResponse) *NullablePublicSettingsInspectResponse {
	return &NullablePublicSettingsInspectResponse{value: val, isSet: true}
}

func (v NullablePublicSettingsInspectResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePublicSettingsInspectResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


