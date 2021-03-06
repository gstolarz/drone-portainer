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

// Extension struct for Extension
type Extension struct {
	// Extension identifier
	Id *int32 `json:"Id,omitempty"`
	// Extension name
	Name *string `json:"Name,omitempty"`
	// Is the extension enabled
	Enabled *bool `json:"Enabled,omitempty"`
	// Short description about the extension
	ShortDescription *string `json:"ShortDescription,omitempty"`
	// URL to the file containing the extension description
	DescriptionURL *string `json:"DescriptionURL,omitempty"`
	// Is the extension available for download and activation
	Available *bool `json:"Available,omitempty"`
	// List of screenshot URLs
	Images *[]string `json:"Images,omitempty"`
	// Icon associated to the extension
	Logo *string `json:"Logo,omitempty"`
	// Extension price
	Price *string `json:"Price,omitempty"`
	// Details about extension pricing
	PriceDescription *string `json:"PriceDescription,omitempty"`
	// URL used to buy the extension
	ShopURL *string `json:"ShopURL,omitempty"`
	// Is an update available for this extension
	UpdateAvailable *bool `json:"UpdateAvailable,omitempty"`
	// Extension version
	Version *string `json:"Version,omitempty"`
	License *LicenseInformation `json:"License,omitempty"`
}

// NewExtension instantiates a new Extension object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewExtension() *Extension {
	this := Extension{}
	return &this
}

// NewExtensionWithDefaults instantiates a new Extension object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewExtensionWithDefaults() *Extension {
	this := Extension{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *Extension) GetId() int32 {
	if o == nil || o.Id == nil {
		var ret int32
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetIdOk() (*int32, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *Extension) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given int32 and assigns it to the Id field.
func (o *Extension) SetId(v int32) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Extension) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Extension) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Extension) SetName(v string) {
	o.Name = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *Extension) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *Extension) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *Extension) SetEnabled(v bool) {
	o.Enabled = &v
}

// GetShortDescription returns the ShortDescription field value if set, zero value otherwise.
func (o *Extension) GetShortDescription() string {
	if o == nil || o.ShortDescription == nil {
		var ret string
		return ret
	}
	return *o.ShortDescription
}

// GetShortDescriptionOk returns a tuple with the ShortDescription field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetShortDescriptionOk() (*string, bool) {
	if o == nil || o.ShortDescription == nil {
		return nil, false
	}
	return o.ShortDescription, true
}

// HasShortDescription returns a boolean if a field has been set.
func (o *Extension) HasShortDescription() bool {
	if o != nil && o.ShortDescription != nil {
		return true
	}

	return false
}

// SetShortDescription gets a reference to the given string and assigns it to the ShortDescription field.
func (o *Extension) SetShortDescription(v string) {
	o.ShortDescription = &v
}

// GetDescriptionURL returns the DescriptionURL field value if set, zero value otherwise.
func (o *Extension) GetDescriptionURL() string {
	if o == nil || o.DescriptionURL == nil {
		var ret string
		return ret
	}
	return *o.DescriptionURL
}

// GetDescriptionURLOk returns a tuple with the DescriptionURL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetDescriptionURLOk() (*string, bool) {
	if o == nil || o.DescriptionURL == nil {
		return nil, false
	}
	return o.DescriptionURL, true
}

// HasDescriptionURL returns a boolean if a field has been set.
func (o *Extension) HasDescriptionURL() bool {
	if o != nil && o.DescriptionURL != nil {
		return true
	}

	return false
}

// SetDescriptionURL gets a reference to the given string and assigns it to the DescriptionURL field.
func (o *Extension) SetDescriptionURL(v string) {
	o.DescriptionURL = &v
}

// GetAvailable returns the Available field value if set, zero value otherwise.
func (o *Extension) GetAvailable() bool {
	if o == nil || o.Available == nil {
		var ret bool
		return ret
	}
	return *o.Available
}

// GetAvailableOk returns a tuple with the Available field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetAvailableOk() (*bool, bool) {
	if o == nil || o.Available == nil {
		return nil, false
	}
	return o.Available, true
}

// HasAvailable returns a boolean if a field has been set.
func (o *Extension) HasAvailable() bool {
	if o != nil && o.Available != nil {
		return true
	}

	return false
}

// SetAvailable gets a reference to the given bool and assigns it to the Available field.
func (o *Extension) SetAvailable(v bool) {
	o.Available = &v
}

// GetImages returns the Images field value if set, zero value otherwise.
func (o *Extension) GetImages() []string {
	if o == nil || o.Images == nil {
		var ret []string
		return ret
	}
	return *o.Images
}

// GetImagesOk returns a tuple with the Images field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetImagesOk() (*[]string, bool) {
	if o == nil || o.Images == nil {
		return nil, false
	}
	return o.Images, true
}

// HasImages returns a boolean if a field has been set.
func (o *Extension) HasImages() bool {
	if o != nil && o.Images != nil {
		return true
	}

	return false
}

// SetImages gets a reference to the given []string and assigns it to the Images field.
func (o *Extension) SetImages(v []string) {
	o.Images = &v
}

// GetLogo returns the Logo field value if set, zero value otherwise.
func (o *Extension) GetLogo() string {
	if o == nil || o.Logo == nil {
		var ret string
		return ret
	}
	return *o.Logo
}

// GetLogoOk returns a tuple with the Logo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetLogoOk() (*string, bool) {
	if o == nil || o.Logo == nil {
		return nil, false
	}
	return o.Logo, true
}

// HasLogo returns a boolean if a field has been set.
func (o *Extension) HasLogo() bool {
	if o != nil && o.Logo != nil {
		return true
	}

	return false
}

// SetLogo gets a reference to the given string and assigns it to the Logo field.
func (o *Extension) SetLogo(v string) {
	o.Logo = &v
}

// GetPrice returns the Price field value if set, zero value otherwise.
func (o *Extension) GetPrice() string {
	if o == nil || o.Price == nil {
		var ret string
		return ret
	}
	return *o.Price
}

// GetPriceOk returns a tuple with the Price field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetPriceOk() (*string, bool) {
	if o == nil || o.Price == nil {
		return nil, false
	}
	return o.Price, true
}

// HasPrice returns a boolean if a field has been set.
func (o *Extension) HasPrice() bool {
	if o != nil && o.Price != nil {
		return true
	}

	return false
}

// SetPrice gets a reference to the given string and assigns it to the Price field.
func (o *Extension) SetPrice(v string) {
	o.Price = &v
}

// GetPriceDescription returns the PriceDescription field value if set, zero value otherwise.
func (o *Extension) GetPriceDescription() string {
	if o == nil || o.PriceDescription == nil {
		var ret string
		return ret
	}
	return *o.PriceDescription
}

// GetPriceDescriptionOk returns a tuple with the PriceDescription field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetPriceDescriptionOk() (*string, bool) {
	if o == nil || o.PriceDescription == nil {
		return nil, false
	}
	return o.PriceDescription, true
}

// HasPriceDescription returns a boolean if a field has been set.
func (o *Extension) HasPriceDescription() bool {
	if o != nil && o.PriceDescription != nil {
		return true
	}

	return false
}

// SetPriceDescription gets a reference to the given string and assigns it to the PriceDescription field.
func (o *Extension) SetPriceDescription(v string) {
	o.PriceDescription = &v
}

// GetShopURL returns the ShopURL field value if set, zero value otherwise.
func (o *Extension) GetShopURL() string {
	if o == nil || o.ShopURL == nil {
		var ret string
		return ret
	}
	return *o.ShopURL
}

// GetShopURLOk returns a tuple with the ShopURL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetShopURLOk() (*string, bool) {
	if o == nil || o.ShopURL == nil {
		return nil, false
	}
	return o.ShopURL, true
}

// HasShopURL returns a boolean if a field has been set.
func (o *Extension) HasShopURL() bool {
	if o != nil && o.ShopURL != nil {
		return true
	}

	return false
}

// SetShopURL gets a reference to the given string and assigns it to the ShopURL field.
func (o *Extension) SetShopURL(v string) {
	o.ShopURL = &v
}

// GetUpdateAvailable returns the UpdateAvailable field value if set, zero value otherwise.
func (o *Extension) GetUpdateAvailable() bool {
	if o == nil || o.UpdateAvailable == nil {
		var ret bool
		return ret
	}
	return *o.UpdateAvailable
}

// GetUpdateAvailableOk returns a tuple with the UpdateAvailable field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetUpdateAvailableOk() (*bool, bool) {
	if o == nil || o.UpdateAvailable == nil {
		return nil, false
	}
	return o.UpdateAvailable, true
}

// HasUpdateAvailable returns a boolean if a field has been set.
func (o *Extension) HasUpdateAvailable() bool {
	if o != nil && o.UpdateAvailable != nil {
		return true
	}

	return false
}

// SetUpdateAvailable gets a reference to the given bool and assigns it to the UpdateAvailable field.
func (o *Extension) SetUpdateAvailable(v bool) {
	o.UpdateAvailable = &v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *Extension) GetVersion() string {
	if o == nil || o.Version == nil {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetVersionOk() (*string, bool) {
	if o == nil || o.Version == nil {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *Extension) HasVersion() bool {
	if o != nil && o.Version != nil {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *Extension) SetVersion(v string) {
	o.Version = &v
}

// GetLicense returns the License field value if set, zero value otherwise.
func (o *Extension) GetLicense() LicenseInformation {
	if o == nil || o.License == nil {
		var ret LicenseInformation
		return ret
	}
	return *o.License
}

// GetLicenseOk returns a tuple with the License field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Extension) GetLicenseOk() (*LicenseInformation, bool) {
	if o == nil || o.License == nil {
		return nil, false
	}
	return o.License, true
}

// HasLicense returns a boolean if a field has been set.
func (o *Extension) HasLicense() bool {
	if o != nil && o.License != nil {
		return true
	}

	return false
}

// SetLicense gets a reference to the given LicenseInformation and assigns it to the License field.
func (o *Extension) SetLicense(v LicenseInformation) {
	o.License = &v
}

func (o Extension) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["Id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["Name"] = o.Name
	}
	if o.Enabled != nil {
		toSerialize["Enabled"] = o.Enabled
	}
	if o.ShortDescription != nil {
		toSerialize["ShortDescription"] = o.ShortDescription
	}
	if o.DescriptionURL != nil {
		toSerialize["DescriptionURL"] = o.DescriptionURL
	}
	if o.Available != nil {
		toSerialize["Available"] = o.Available
	}
	if o.Images != nil {
		toSerialize["Images"] = o.Images
	}
	if o.Logo != nil {
		toSerialize["Logo"] = o.Logo
	}
	if o.Price != nil {
		toSerialize["Price"] = o.Price
	}
	if o.PriceDescription != nil {
		toSerialize["PriceDescription"] = o.PriceDescription
	}
	if o.ShopURL != nil {
		toSerialize["ShopURL"] = o.ShopURL
	}
	if o.UpdateAvailable != nil {
		toSerialize["UpdateAvailable"] = o.UpdateAvailable
	}
	if o.Version != nil {
		toSerialize["Version"] = o.Version
	}
	if o.License != nil {
		toSerialize["License"] = o.License
	}
	return json.Marshal(toSerialize)
}

type NullableExtension struct {
	value *Extension
	isSet bool
}

func (v NullableExtension) Get() *Extension {
	return v.value
}

func (v *NullableExtension) Set(val *Extension) {
	v.value = val
	v.isSet = true
}

func (v NullableExtension) IsSet() bool {
	return v.isSet
}

func (v *NullableExtension) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableExtension(val *Extension) *NullableExtension {
	return &NullableExtension{value: val, isSet: true}
}

func (v NullableExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableExtension) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


