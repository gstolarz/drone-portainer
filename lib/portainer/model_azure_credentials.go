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

// AzureCredentials struct for AzureCredentials
type AzureCredentials struct {
	// Azure application ID
	ApplicationID *string `json:"ApplicationID,omitempty"`
	// Azure tenant ID
	TenantID *string `json:"TenantID,omitempty"`
	// Azure authentication key
	AuthenticationKey *string `json:"AuthenticationKey,omitempty"`
}

// NewAzureCredentials instantiates a new AzureCredentials object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAzureCredentials() *AzureCredentials {
	this := AzureCredentials{}
	return &this
}

// NewAzureCredentialsWithDefaults instantiates a new AzureCredentials object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAzureCredentialsWithDefaults() *AzureCredentials {
	this := AzureCredentials{}
	return &this
}

// GetApplicationID returns the ApplicationID field value if set, zero value otherwise.
func (o *AzureCredentials) GetApplicationID() string {
	if o == nil || o.ApplicationID == nil {
		var ret string
		return ret
	}
	return *o.ApplicationID
}

// GetApplicationIDOk returns a tuple with the ApplicationID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AzureCredentials) GetApplicationIDOk() (*string, bool) {
	if o == nil || o.ApplicationID == nil {
		return nil, false
	}
	return o.ApplicationID, true
}

// HasApplicationID returns a boolean if a field has been set.
func (o *AzureCredentials) HasApplicationID() bool {
	if o != nil && o.ApplicationID != nil {
		return true
	}

	return false
}

// SetApplicationID gets a reference to the given string and assigns it to the ApplicationID field.
func (o *AzureCredentials) SetApplicationID(v string) {
	o.ApplicationID = &v
}

// GetTenantID returns the TenantID field value if set, zero value otherwise.
func (o *AzureCredentials) GetTenantID() string {
	if o == nil || o.TenantID == nil {
		var ret string
		return ret
	}
	return *o.TenantID
}

// GetTenantIDOk returns a tuple with the TenantID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AzureCredentials) GetTenantIDOk() (*string, bool) {
	if o == nil || o.TenantID == nil {
		return nil, false
	}
	return o.TenantID, true
}

// HasTenantID returns a boolean if a field has been set.
func (o *AzureCredentials) HasTenantID() bool {
	if o != nil && o.TenantID != nil {
		return true
	}

	return false
}

// SetTenantID gets a reference to the given string and assigns it to the TenantID field.
func (o *AzureCredentials) SetTenantID(v string) {
	o.TenantID = &v
}

// GetAuthenticationKey returns the AuthenticationKey field value if set, zero value otherwise.
func (o *AzureCredentials) GetAuthenticationKey() string {
	if o == nil || o.AuthenticationKey == nil {
		var ret string
		return ret
	}
	return *o.AuthenticationKey
}

// GetAuthenticationKeyOk returns a tuple with the AuthenticationKey field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AzureCredentials) GetAuthenticationKeyOk() (*string, bool) {
	if o == nil || o.AuthenticationKey == nil {
		return nil, false
	}
	return o.AuthenticationKey, true
}

// HasAuthenticationKey returns a boolean if a field has been set.
func (o *AzureCredentials) HasAuthenticationKey() bool {
	if o != nil && o.AuthenticationKey != nil {
		return true
	}

	return false
}

// SetAuthenticationKey gets a reference to the given string and assigns it to the AuthenticationKey field.
func (o *AzureCredentials) SetAuthenticationKey(v string) {
	o.AuthenticationKey = &v
}

func (o AzureCredentials) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.ApplicationID != nil {
		toSerialize["ApplicationID"] = o.ApplicationID
	}
	if o.TenantID != nil {
		toSerialize["TenantID"] = o.TenantID
	}
	if o.AuthenticationKey != nil {
		toSerialize["AuthenticationKey"] = o.AuthenticationKey
	}
	return json.Marshal(toSerialize)
}

type NullableAzureCredentials struct {
	value *AzureCredentials
	isSet bool
}

func (v NullableAzureCredentials) Get() *AzureCredentials {
	return v.value
}

func (v *NullableAzureCredentials) Set(val *AzureCredentials) {
	v.value = val
	v.isSet = true
}

func (v NullableAzureCredentials) IsSet() bool {
	return v.isSet
}

func (v *NullableAzureCredentials) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAzureCredentials(val *AzureCredentials) *NullableAzureCredentials {
	return &NullableAzureCredentials{value: val, isSet: true}
}

func (v NullableAzureCredentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAzureCredentials) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


