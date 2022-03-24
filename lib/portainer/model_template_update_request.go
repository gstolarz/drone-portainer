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

// TemplateUpdateRequest struct for TemplateUpdateRequest
type TemplateUpdateRequest struct {
	// Template type. Valid values are: 1 (container), 2 (Swarm stack) or 3 (Compose stack)
	Type *int32 `json:"type,omitempty"`
	// Title of the template
	Title *string `json:"title,omitempty"`
	// Description of the template
	Description *string `json:"description,omitempty"`
	// Whether the template should be available to administrators only
	AdministratorOnly *bool `json:"administrator_only,omitempty"`
	// Image associated to a container template. Mandatory for a container template
	Image *string `json:"image,omitempty"`
	Repository *TemplateRepository `json:"repository,omitempty"`
	// Default name for the stack/container to be used on deployment
	Name *string `json:"name,omitempty"`
	// URL of the template's logo
	Logo *string `json:"logo,omitempty"`
	// A list of environment variables used during the template deployment
	Env *[]TemplateEnv `json:"env,omitempty"`
	// A note that will be displayed in the UI. Supports HTML content
	Note *string `json:"note,omitempty"`
	// Platform associated to the template. Valid values are: 'linux', 'windows' or leave empty for multi-platform
	Platform *string `json:"platform,omitempty"`
	// A list of categories associated to the template
	Categories *[]string `json:"categories,omitempty"`
	// The URL of a registry associated to the image for a container template
	Registry *string `json:"registry,omitempty"`
	// The command that will be executed in a container template
	Command *string `json:"command,omitempty"`
	// Name of a network that will be used on container deployment if it exists inside the environment
	Network *string `json:"network,omitempty"`
	// A list of volumes used during the container template deployment
	Volumes *[]TemplateVolume `json:"volumes,omitempty"`
	// A list of ports exposed by the container
	Ports *[]string `json:"ports,omitempty"`
	// Container labels
	Labels *[]Pair `json:"labels,omitempty"`
	// Whether the container should be started in privileged mode
	Privileged *bool `json:"privileged,omitempty"`
	// Whether the container should be started in interactive mode (-i -t equivalent on the CLI)
	Interactive *bool `json:"interactive,omitempty"`
	// Container restart policy
	RestartPolicy *string `json:"restart_policy,omitempty"`
	// Container hostname
	Hostname *string `json:"hostname,omitempty"`
}

// NewTemplateUpdateRequest instantiates a new TemplateUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTemplateUpdateRequest() *TemplateUpdateRequest {
	this := TemplateUpdateRequest{}
	return &this
}

// NewTemplateUpdateRequestWithDefaults instantiates a new TemplateUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTemplateUpdateRequestWithDefaults() *TemplateUpdateRequest {
	this := TemplateUpdateRequest{}
	return &this
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetType() int32 {
	if o == nil || o.Type == nil {
		var ret int32
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetTypeOk() (*int32, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given int32 and assigns it to the Type field.
func (o *TemplateUpdateRequest) SetType(v int32) {
	o.Type = &v
}

// GetTitle returns the Title field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetTitle() string {
	if o == nil || o.Title == nil {
		var ret string
		return ret
	}
	return *o.Title
}

// GetTitleOk returns a tuple with the Title field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetTitleOk() (*string, bool) {
	if o == nil || o.Title == nil {
		return nil, false
	}
	return o.Title, true
}

// HasTitle returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasTitle() bool {
	if o != nil && o.Title != nil {
		return true
	}

	return false
}

// SetTitle gets a reference to the given string and assigns it to the Title field.
func (o *TemplateUpdateRequest) SetTitle(v string) {
	o.Title = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *TemplateUpdateRequest) SetDescription(v string) {
	o.Description = &v
}

// GetAdministratorOnly returns the AdministratorOnly field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetAdministratorOnly() bool {
	if o == nil || o.AdministratorOnly == nil {
		var ret bool
		return ret
	}
	return *o.AdministratorOnly
}

// GetAdministratorOnlyOk returns a tuple with the AdministratorOnly field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetAdministratorOnlyOk() (*bool, bool) {
	if o == nil || o.AdministratorOnly == nil {
		return nil, false
	}
	return o.AdministratorOnly, true
}

// HasAdministratorOnly returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasAdministratorOnly() bool {
	if o != nil && o.AdministratorOnly != nil {
		return true
	}

	return false
}

// SetAdministratorOnly gets a reference to the given bool and assigns it to the AdministratorOnly field.
func (o *TemplateUpdateRequest) SetAdministratorOnly(v bool) {
	o.AdministratorOnly = &v
}

// GetImage returns the Image field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetImage() string {
	if o == nil || o.Image == nil {
		var ret string
		return ret
	}
	return *o.Image
}

// GetImageOk returns a tuple with the Image field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetImageOk() (*string, bool) {
	if o == nil || o.Image == nil {
		return nil, false
	}
	return o.Image, true
}

// HasImage returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasImage() bool {
	if o != nil && o.Image != nil {
		return true
	}

	return false
}

// SetImage gets a reference to the given string and assigns it to the Image field.
func (o *TemplateUpdateRequest) SetImage(v string) {
	o.Image = &v
}

// GetRepository returns the Repository field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetRepository() TemplateRepository {
	if o == nil || o.Repository == nil {
		var ret TemplateRepository
		return ret
	}
	return *o.Repository
}

// GetRepositoryOk returns a tuple with the Repository field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetRepositoryOk() (*TemplateRepository, bool) {
	if o == nil || o.Repository == nil {
		return nil, false
	}
	return o.Repository, true
}

// HasRepository returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasRepository() bool {
	if o != nil && o.Repository != nil {
		return true
	}

	return false
}

// SetRepository gets a reference to the given TemplateRepository and assigns it to the Repository field.
func (o *TemplateUpdateRequest) SetRepository(v TemplateRepository) {
	o.Repository = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *TemplateUpdateRequest) SetName(v string) {
	o.Name = &v
}

// GetLogo returns the Logo field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetLogo() string {
	if o == nil || o.Logo == nil {
		var ret string
		return ret
	}
	return *o.Logo
}

// GetLogoOk returns a tuple with the Logo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetLogoOk() (*string, bool) {
	if o == nil || o.Logo == nil {
		return nil, false
	}
	return o.Logo, true
}

// HasLogo returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasLogo() bool {
	if o != nil && o.Logo != nil {
		return true
	}

	return false
}

// SetLogo gets a reference to the given string and assigns it to the Logo field.
func (o *TemplateUpdateRequest) SetLogo(v string) {
	o.Logo = &v
}

// GetEnv returns the Env field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetEnv() []TemplateEnv {
	if o == nil || o.Env == nil {
		var ret []TemplateEnv
		return ret
	}
	return *o.Env
}

// GetEnvOk returns a tuple with the Env field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetEnvOk() (*[]TemplateEnv, bool) {
	if o == nil || o.Env == nil {
		return nil, false
	}
	return o.Env, true
}

// HasEnv returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasEnv() bool {
	if o != nil && o.Env != nil {
		return true
	}

	return false
}

// SetEnv gets a reference to the given []TemplateEnv and assigns it to the Env field.
func (o *TemplateUpdateRequest) SetEnv(v []TemplateEnv) {
	o.Env = &v
}

// GetNote returns the Note field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetNote() string {
	if o == nil || o.Note == nil {
		var ret string
		return ret
	}
	return *o.Note
}

// GetNoteOk returns a tuple with the Note field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetNoteOk() (*string, bool) {
	if o == nil || o.Note == nil {
		return nil, false
	}
	return o.Note, true
}

// HasNote returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasNote() bool {
	if o != nil && o.Note != nil {
		return true
	}

	return false
}

// SetNote gets a reference to the given string and assigns it to the Note field.
func (o *TemplateUpdateRequest) SetNote(v string) {
	o.Note = &v
}

// GetPlatform returns the Platform field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetPlatform() string {
	if o == nil || o.Platform == nil {
		var ret string
		return ret
	}
	return *o.Platform
}

// GetPlatformOk returns a tuple with the Platform field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetPlatformOk() (*string, bool) {
	if o == nil || o.Platform == nil {
		return nil, false
	}
	return o.Platform, true
}

// HasPlatform returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasPlatform() bool {
	if o != nil && o.Platform != nil {
		return true
	}

	return false
}

// SetPlatform gets a reference to the given string and assigns it to the Platform field.
func (o *TemplateUpdateRequest) SetPlatform(v string) {
	o.Platform = &v
}

// GetCategories returns the Categories field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetCategories() []string {
	if o == nil || o.Categories == nil {
		var ret []string
		return ret
	}
	return *o.Categories
}

// GetCategoriesOk returns a tuple with the Categories field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetCategoriesOk() (*[]string, bool) {
	if o == nil || o.Categories == nil {
		return nil, false
	}
	return o.Categories, true
}

// HasCategories returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasCategories() bool {
	if o != nil && o.Categories != nil {
		return true
	}

	return false
}

// SetCategories gets a reference to the given []string and assigns it to the Categories field.
func (o *TemplateUpdateRequest) SetCategories(v []string) {
	o.Categories = &v
}

// GetRegistry returns the Registry field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetRegistry() string {
	if o == nil || o.Registry == nil {
		var ret string
		return ret
	}
	return *o.Registry
}

// GetRegistryOk returns a tuple with the Registry field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetRegistryOk() (*string, bool) {
	if o == nil || o.Registry == nil {
		return nil, false
	}
	return o.Registry, true
}

// HasRegistry returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasRegistry() bool {
	if o != nil && o.Registry != nil {
		return true
	}

	return false
}

// SetRegistry gets a reference to the given string and assigns it to the Registry field.
func (o *TemplateUpdateRequest) SetRegistry(v string) {
	o.Registry = &v
}

// GetCommand returns the Command field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetCommand() string {
	if o == nil || o.Command == nil {
		var ret string
		return ret
	}
	return *o.Command
}

// GetCommandOk returns a tuple with the Command field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetCommandOk() (*string, bool) {
	if o == nil || o.Command == nil {
		return nil, false
	}
	return o.Command, true
}

// HasCommand returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasCommand() bool {
	if o != nil && o.Command != nil {
		return true
	}

	return false
}

// SetCommand gets a reference to the given string and assigns it to the Command field.
func (o *TemplateUpdateRequest) SetCommand(v string) {
	o.Command = &v
}

// GetNetwork returns the Network field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetNetwork() string {
	if o == nil || o.Network == nil {
		var ret string
		return ret
	}
	return *o.Network
}

// GetNetworkOk returns a tuple with the Network field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetNetworkOk() (*string, bool) {
	if o == nil || o.Network == nil {
		return nil, false
	}
	return o.Network, true
}

// HasNetwork returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasNetwork() bool {
	if o != nil && o.Network != nil {
		return true
	}

	return false
}

// SetNetwork gets a reference to the given string and assigns it to the Network field.
func (o *TemplateUpdateRequest) SetNetwork(v string) {
	o.Network = &v
}

// GetVolumes returns the Volumes field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetVolumes() []TemplateVolume {
	if o == nil || o.Volumes == nil {
		var ret []TemplateVolume
		return ret
	}
	return *o.Volumes
}

// GetVolumesOk returns a tuple with the Volumes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetVolumesOk() (*[]TemplateVolume, bool) {
	if o == nil || o.Volumes == nil {
		return nil, false
	}
	return o.Volumes, true
}

// HasVolumes returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasVolumes() bool {
	if o != nil && o.Volumes != nil {
		return true
	}

	return false
}

// SetVolumes gets a reference to the given []TemplateVolume and assigns it to the Volumes field.
func (o *TemplateUpdateRequest) SetVolumes(v []TemplateVolume) {
	o.Volumes = &v
}

// GetPorts returns the Ports field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetPorts() []string {
	if o == nil || o.Ports == nil {
		var ret []string
		return ret
	}
	return *o.Ports
}

// GetPortsOk returns a tuple with the Ports field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetPortsOk() (*[]string, bool) {
	if o == nil || o.Ports == nil {
		return nil, false
	}
	return o.Ports, true
}

// HasPorts returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasPorts() bool {
	if o != nil && o.Ports != nil {
		return true
	}

	return false
}

// SetPorts gets a reference to the given []string and assigns it to the Ports field.
func (o *TemplateUpdateRequest) SetPorts(v []string) {
	o.Ports = &v
}

// GetLabels returns the Labels field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetLabels() []Pair {
	if o == nil || o.Labels == nil {
		var ret []Pair
		return ret
	}
	return *o.Labels
}

// GetLabelsOk returns a tuple with the Labels field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetLabelsOk() (*[]Pair, bool) {
	if o == nil || o.Labels == nil {
		return nil, false
	}
	return o.Labels, true
}

// HasLabels returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasLabels() bool {
	if o != nil && o.Labels != nil {
		return true
	}

	return false
}

// SetLabels gets a reference to the given []Pair and assigns it to the Labels field.
func (o *TemplateUpdateRequest) SetLabels(v []Pair) {
	o.Labels = &v
}

// GetPrivileged returns the Privileged field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetPrivileged() bool {
	if o == nil || o.Privileged == nil {
		var ret bool
		return ret
	}
	return *o.Privileged
}

// GetPrivilegedOk returns a tuple with the Privileged field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetPrivilegedOk() (*bool, bool) {
	if o == nil || o.Privileged == nil {
		return nil, false
	}
	return o.Privileged, true
}

// HasPrivileged returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasPrivileged() bool {
	if o != nil && o.Privileged != nil {
		return true
	}

	return false
}

// SetPrivileged gets a reference to the given bool and assigns it to the Privileged field.
func (o *TemplateUpdateRequest) SetPrivileged(v bool) {
	o.Privileged = &v
}

// GetInteractive returns the Interactive field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetInteractive() bool {
	if o == nil || o.Interactive == nil {
		var ret bool
		return ret
	}
	return *o.Interactive
}

// GetInteractiveOk returns a tuple with the Interactive field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetInteractiveOk() (*bool, bool) {
	if o == nil || o.Interactive == nil {
		return nil, false
	}
	return o.Interactive, true
}

// HasInteractive returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasInteractive() bool {
	if o != nil && o.Interactive != nil {
		return true
	}

	return false
}

// SetInteractive gets a reference to the given bool and assigns it to the Interactive field.
func (o *TemplateUpdateRequest) SetInteractive(v bool) {
	o.Interactive = &v
}

// GetRestartPolicy returns the RestartPolicy field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetRestartPolicy() string {
	if o == nil || o.RestartPolicy == nil {
		var ret string
		return ret
	}
	return *o.RestartPolicy
}

// GetRestartPolicyOk returns a tuple with the RestartPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetRestartPolicyOk() (*string, bool) {
	if o == nil || o.RestartPolicy == nil {
		return nil, false
	}
	return o.RestartPolicy, true
}

// HasRestartPolicy returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasRestartPolicy() bool {
	if o != nil && o.RestartPolicy != nil {
		return true
	}

	return false
}

// SetRestartPolicy gets a reference to the given string and assigns it to the RestartPolicy field.
func (o *TemplateUpdateRequest) SetRestartPolicy(v string) {
	o.RestartPolicy = &v
}

// GetHostname returns the Hostname field value if set, zero value otherwise.
func (o *TemplateUpdateRequest) GetHostname() string {
	if o == nil || o.Hostname == nil {
		var ret string
		return ret
	}
	return *o.Hostname
}

// GetHostnameOk returns a tuple with the Hostname field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TemplateUpdateRequest) GetHostnameOk() (*string, bool) {
	if o == nil || o.Hostname == nil {
		return nil, false
	}
	return o.Hostname, true
}

// HasHostname returns a boolean if a field has been set.
func (o *TemplateUpdateRequest) HasHostname() bool {
	if o != nil && o.Hostname != nil {
		return true
	}

	return false
}

// SetHostname gets a reference to the given string and assigns it to the Hostname field.
func (o *TemplateUpdateRequest) SetHostname(v string) {
	o.Hostname = &v
}

func (o TemplateUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Type != nil {
		toSerialize["type"] = o.Type
	}
	if o.Title != nil {
		toSerialize["title"] = o.Title
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	if o.AdministratorOnly != nil {
		toSerialize["administrator_only"] = o.AdministratorOnly
	}
	if o.Image != nil {
		toSerialize["image"] = o.Image
	}
	if o.Repository != nil {
		toSerialize["repository"] = o.Repository
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Logo != nil {
		toSerialize["logo"] = o.Logo
	}
	if o.Env != nil {
		toSerialize["env"] = o.Env
	}
	if o.Note != nil {
		toSerialize["note"] = o.Note
	}
	if o.Platform != nil {
		toSerialize["platform"] = o.Platform
	}
	if o.Categories != nil {
		toSerialize["categories"] = o.Categories
	}
	if o.Registry != nil {
		toSerialize["registry"] = o.Registry
	}
	if o.Command != nil {
		toSerialize["command"] = o.Command
	}
	if o.Network != nil {
		toSerialize["network"] = o.Network
	}
	if o.Volumes != nil {
		toSerialize["volumes"] = o.Volumes
	}
	if o.Ports != nil {
		toSerialize["ports"] = o.Ports
	}
	if o.Labels != nil {
		toSerialize["labels"] = o.Labels
	}
	if o.Privileged != nil {
		toSerialize["privileged"] = o.Privileged
	}
	if o.Interactive != nil {
		toSerialize["interactive"] = o.Interactive
	}
	if o.RestartPolicy != nil {
		toSerialize["restart_policy"] = o.RestartPolicy
	}
	if o.Hostname != nil {
		toSerialize["hostname"] = o.Hostname
	}
	return json.Marshal(toSerialize)
}

type NullableTemplateUpdateRequest struct {
	value *TemplateUpdateRequest
	isSet bool
}

func (v NullableTemplateUpdateRequest) Get() *TemplateUpdateRequest {
	return v.value
}

func (v *NullableTemplateUpdateRequest) Set(val *TemplateUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableTemplateUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableTemplateUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTemplateUpdateRequest(val *TemplateUpdateRequest) *NullableTemplateUpdateRequest {
	return &NullableTemplateUpdateRequest{value: val, isSet: true}
}

func (v NullableTemplateUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTemplateUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


