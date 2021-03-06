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

// LDAPSettings struct for LDAPSettings
type LDAPSettings struct {
	// Enable this option if the server is configured for Anonymous access. When enabled, ReaderDN and Password will not be used.
	AnonymousMode *bool `json:"AnonymousMode,omitempty"`
	// Account that will be used to search for users
	ReaderDN *string `json:"ReaderDN,omitempty"`
	// Password of the account that will be used to search users
	Password *string `json:"Password,omitempty"`
	// URL or IP address of the LDAP server
	URL *string `json:"URL,omitempty"`
	TLSConfig *TLSConfiguration `json:"TLSConfig,omitempty"`
	// Whether LDAP connection should use StartTLS
	StartTLS *bool `json:"StartTLS,omitempty"`
	SearchSettings *[]LDAPSearchSettings `json:"SearchSettings,omitempty"`
	GroupSearchSettings *[]LDAPGroupSearchSettings `json:"GroupSearchSettings,omitempty"`
	// Automatically provision users and assign them to matching LDAP group names
	AutoCreateUsers *bool `json:"AutoCreateUsers,omitempty"`
}

// NewLDAPSettings instantiates a new LDAPSettings object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewLDAPSettings() *LDAPSettings {
	this := LDAPSettings{}
	return &this
}

// NewLDAPSettingsWithDefaults instantiates a new LDAPSettings object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewLDAPSettingsWithDefaults() *LDAPSettings {
	this := LDAPSettings{}
	return &this
}

// GetAnonymousMode returns the AnonymousMode field value if set, zero value otherwise.
func (o *LDAPSettings) GetAnonymousMode() bool {
	if o == nil || o.AnonymousMode == nil {
		var ret bool
		return ret
	}
	return *o.AnonymousMode
}

// GetAnonymousModeOk returns a tuple with the AnonymousMode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetAnonymousModeOk() (*bool, bool) {
	if o == nil || o.AnonymousMode == nil {
		return nil, false
	}
	return o.AnonymousMode, true
}

// HasAnonymousMode returns a boolean if a field has been set.
func (o *LDAPSettings) HasAnonymousMode() bool {
	if o != nil && o.AnonymousMode != nil {
		return true
	}

	return false
}

// SetAnonymousMode gets a reference to the given bool and assigns it to the AnonymousMode field.
func (o *LDAPSettings) SetAnonymousMode(v bool) {
	o.AnonymousMode = &v
}

// GetReaderDN returns the ReaderDN field value if set, zero value otherwise.
func (o *LDAPSettings) GetReaderDN() string {
	if o == nil || o.ReaderDN == nil {
		var ret string
		return ret
	}
	return *o.ReaderDN
}

// GetReaderDNOk returns a tuple with the ReaderDN field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetReaderDNOk() (*string, bool) {
	if o == nil || o.ReaderDN == nil {
		return nil, false
	}
	return o.ReaderDN, true
}

// HasReaderDN returns a boolean if a field has been set.
func (o *LDAPSettings) HasReaderDN() bool {
	if o != nil && o.ReaderDN != nil {
		return true
	}

	return false
}

// SetReaderDN gets a reference to the given string and assigns it to the ReaderDN field.
func (o *LDAPSettings) SetReaderDN(v string) {
	o.ReaderDN = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *LDAPSettings) GetPassword() string {
	if o == nil || o.Password == nil {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetPasswordOk() (*string, bool) {
	if o == nil || o.Password == nil {
		return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *LDAPSettings) HasPassword() bool {
	if o != nil && o.Password != nil {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *LDAPSettings) SetPassword(v string) {
	o.Password = &v
}

// GetURL returns the URL field value if set, zero value otherwise.
func (o *LDAPSettings) GetURL() string {
	if o == nil || o.URL == nil {
		var ret string
		return ret
	}
	return *o.URL
}

// GetURLOk returns a tuple with the URL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetURLOk() (*string, bool) {
	if o == nil || o.URL == nil {
		return nil, false
	}
	return o.URL, true
}

// HasURL returns a boolean if a field has been set.
func (o *LDAPSettings) HasURL() bool {
	if o != nil && o.URL != nil {
		return true
	}

	return false
}

// SetURL gets a reference to the given string and assigns it to the URL field.
func (o *LDAPSettings) SetURL(v string) {
	o.URL = &v
}

// GetTLSConfig returns the TLSConfig field value if set, zero value otherwise.
func (o *LDAPSettings) GetTLSConfig() TLSConfiguration {
	if o == nil || o.TLSConfig == nil {
		var ret TLSConfiguration
		return ret
	}
	return *o.TLSConfig
}

// GetTLSConfigOk returns a tuple with the TLSConfig field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetTLSConfigOk() (*TLSConfiguration, bool) {
	if o == nil || o.TLSConfig == nil {
		return nil, false
	}
	return o.TLSConfig, true
}

// HasTLSConfig returns a boolean if a field has been set.
func (o *LDAPSettings) HasTLSConfig() bool {
	if o != nil && o.TLSConfig != nil {
		return true
	}

	return false
}

// SetTLSConfig gets a reference to the given TLSConfiguration and assigns it to the TLSConfig field.
func (o *LDAPSettings) SetTLSConfig(v TLSConfiguration) {
	o.TLSConfig = &v
}

// GetStartTLS returns the StartTLS field value if set, zero value otherwise.
func (o *LDAPSettings) GetStartTLS() bool {
	if o == nil || o.StartTLS == nil {
		var ret bool
		return ret
	}
	return *o.StartTLS
}

// GetStartTLSOk returns a tuple with the StartTLS field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetStartTLSOk() (*bool, bool) {
	if o == nil || o.StartTLS == nil {
		return nil, false
	}
	return o.StartTLS, true
}

// HasStartTLS returns a boolean if a field has been set.
func (o *LDAPSettings) HasStartTLS() bool {
	if o != nil && o.StartTLS != nil {
		return true
	}

	return false
}

// SetStartTLS gets a reference to the given bool and assigns it to the StartTLS field.
func (o *LDAPSettings) SetStartTLS(v bool) {
	o.StartTLS = &v
}

// GetSearchSettings returns the SearchSettings field value if set, zero value otherwise.
func (o *LDAPSettings) GetSearchSettings() []LDAPSearchSettings {
	if o == nil || o.SearchSettings == nil {
		var ret []LDAPSearchSettings
		return ret
	}
	return *o.SearchSettings
}

// GetSearchSettingsOk returns a tuple with the SearchSettings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetSearchSettingsOk() (*[]LDAPSearchSettings, bool) {
	if o == nil || o.SearchSettings == nil {
		return nil, false
	}
	return o.SearchSettings, true
}

// HasSearchSettings returns a boolean if a field has been set.
func (o *LDAPSettings) HasSearchSettings() bool {
	if o != nil && o.SearchSettings != nil {
		return true
	}

	return false
}

// SetSearchSettings gets a reference to the given []LDAPSearchSettings and assigns it to the SearchSettings field.
func (o *LDAPSettings) SetSearchSettings(v []LDAPSearchSettings) {
	o.SearchSettings = &v
}

// GetGroupSearchSettings returns the GroupSearchSettings field value if set, zero value otherwise.
func (o *LDAPSettings) GetGroupSearchSettings() []LDAPGroupSearchSettings {
	if o == nil || o.GroupSearchSettings == nil {
		var ret []LDAPGroupSearchSettings
		return ret
	}
	return *o.GroupSearchSettings
}

// GetGroupSearchSettingsOk returns a tuple with the GroupSearchSettings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetGroupSearchSettingsOk() (*[]LDAPGroupSearchSettings, bool) {
	if o == nil || o.GroupSearchSettings == nil {
		return nil, false
	}
	return o.GroupSearchSettings, true
}

// HasGroupSearchSettings returns a boolean if a field has been set.
func (o *LDAPSettings) HasGroupSearchSettings() bool {
	if o != nil && o.GroupSearchSettings != nil {
		return true
	}

	return false
}

// SetGroupSearchSettings gets a reference to the given []LDAPGroupSearchSettings and assigns it to the GroupSearchSettings field.
func (o *LDAPSettings) SetGroupSearchSettings(v []LDAPGroupSearchSettings) {
	o.GroupSearchSettings = &v
}

// GetAutoCreateUsers returns the AutoCreateUsers field value if set, zero value otherwise.
func (o *LDAPSettings) GetAutoCreateUsers() bool {
	if o == nil || o.AutoCreateUsers == nil {
		var ret bool
		return ret
	}
	return *o.AutoCreateUsers
}

// GetAutoCreateUsersOk returns a tuple with the AutoCreateUsers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LDAPSettings) GetAutoCreateUsersOk() (*bool, bool) {
	if o == nil || o.AutoCreateUsers == nil {
		return nil, false
	}
	return o.AutoCreateUsers, true
}

// HasAutoCreateUsers returns a boolean if a field has been set.
func (o *LDAPSettings) HasAutoCreateUsers() bool {
	if o != nil && o.AutoCreateUsers != nil {
		return true
	}

	return false
}

// SetAutoCreateUsers gets a reference to the given bool and assigns it to the AutoCreateUsers field.
func (o *LDAPSettings) SetAutoCreateUsers(v bool) {
	o.AutoCreateUsers = &v
}

func (o LDAPSettings) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.AnonymousMode != nil {
		toSerialize["AnonymousMode"] = o.AnonymousMode
	}
	if o.ReaderDN != nil {
		toSerialize["ReaderDN"] = o.ReaderDN
	}
	if o.Password != nil {
		toSerialize["Password"] = o.Password
	}
	if o.URL != nil {
		toSerialize["URL"] = o.URL
	}
	if o.TLSConfig != nil {
		toSerialize["TLSConfig"] = o.TLSConfig
	}
	if o.StartTLS != nil {
		toSerialize["StartTLS"] = o.StartTLS
	}
	if o.SearchSettings != nil {
		toSerialize["SearchSettings"] = o.SearchSettings
	}
	if o.GroupSearchSettings != nil {
		toSerialize["GroupSearchSettings"] = o.GroupSearchSettings
	}
	if o.AutoCreateUsers != nil {
		toSerialize["AutoCreateUsers"] = o.AutoCreateUsers
	}
	return json.Marshal(toSerialize)
}

type NullableLDAPSettings struct {
	value *LDAPSettings
	isSet bool
}

func (v NullableLDAPSettings) Get() *LDAPSettings {
	return v.value
}

func (v *NullableLDAPSettings) Set(val *LDAPSettings) {
	v.value = val
	v.isSet = true
}

func (v NullableLDAPSettings) IsSet() bool {
	return v.isSet
}

func (v *NullableLDAPSettings) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableLDAPSettings(val *LDAPSettings) *NullableLDAPSettings {
	return &NullableLDAPSettings{value: val, isSet: true}
}

func (v NullableLDAPSettings) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableLDAPSettings) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


