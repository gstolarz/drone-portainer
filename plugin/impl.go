package plugin

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/urfave/cli/v2"

	"github.com/gstolarz/drone-portainer/lib/portainer"
)

// Settings for the plugin.
type Settings struct {
	Portainer string
	Insecure  bool

	Username string
	Password string

	Endpoint   string
	endpointId int32

	Stack string
	File  string

	Environment  cli.StringSlice
	environments map[string]interface{}

	Networks cli.StringSlice
	networks map[string]network

	Configs cli.StringSlice
	configs map[string]config

	removeConfigs []string

	jwt     string
	swarmId string

	docker *client.Client
}

type network struct {
	Driver    string
	Encrypted bool
}

type config struct {
	File        string
	Data        string
	Template    string
	Environment string
}

// Validate handles the settings validation of the plugin.
func (p *Plugin) Validate() error {
	// Validation of the settings.
	if len(p.settings.Portainer) == 0 {
		return fmt.Errorf("no Portainer URL provided")
	}

	if len(p.settings.Username) == 0 {
		return fmt.Errorf("no Portainer username provided")
	}

	if len(p.settings.Password) == 0 {
		return fmt.Errorf("no Portainer password provided")
	}

	if len(p.settings.Stack) == 0 {
		return fmt.Errorf("no Portainer stack provided")
	}

	if len(p.settings.File) == 0 {
		p.settings.File = p.settings.Stack + ".yml"
	}

	environments := strings.Join(p.settings.Environment.Value(), ",")
	if len(environments) != 0 {
		err := json.Unmarshal([]byte(environments), &p.settings.environments)
		if err != nil {
			return fmt.Errorf("error while unmarshalling environments: %w", err)
		}
	}

	networks := strings.Join(p.settings.Networks.Value(), ",")
	if len(networks) != 0 {
		err := json.Unmarshal([]byte(networks), &p.settings.networks)
		if err != nil {
			return fmt.Errorf("error while unmarshalling networks: %w", err)
		}

		for _, network := range p.settings.networks {
			if len(network.Driver) == 0 {
				return fmt.Errorf("no network driver provided")
			}
		}
	}

	configs := strings.Join(p.settings.Configs.Value(), ",")
	if len(configs) != 0 {
		err := json.Unmarshal([]byte(configs), &p.settings.configs)
		if err != nil {
			return fmt.Errorf("error while unmarshalling configs: %w", err)
		}

		for _, config := range p.settings.configs {
			if len(config.Data) == 0 && len(config.File) == 0 {
				return fmt.Errorf("no config data or file provided")
			}
		}
	}

	return nil
}

// Execute provides the implementation of the plugin.
func (p *Plugin) Execute() error {
	portainerUrl, err := url.Parse(p.settings.Portainer)
	if err != nil {
		return fmt.Errorf("error while parsing url: %w", err)
	}

	portainerUrl.Path = path.Join(portainerUrl.Path, "api")

	cfg := portainer.NewConfiguration()
	cfg.Servers = portainer.ServerConfigurations{{URL: portainerUrl.String()}}

	client := portainer.NewAPIClient(cfg)

	if p.settings.Insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	ctx := context.Background()

	auth, _, err := client.AuthApi.AuthenticateUser(ctx).
		Body(portainer.AuthenticateUserRequest{
			Username: p.settings.Username,
			Password: p.settings.Password,
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("error while authenticating user: %w", err)
	}

	p.settings.jwt = *auth.Jwt

	ctx = context.WithValue(ctx, portainer.ContextAPIKeys, map[string]portainer.APIKey{"jwt": {Key: p.settings.jwt}})

	endpoints, _, err := client.EndpointsApi.EndpointList(ctx).
		Execute()
	if err != nil {
		return fmt.Errorf("error while retrieving endpoint list: %w", err)
	}

	if len(endpoints) == 0 {
		return fmt.Errorf("no endpoints")
	}

	var endpoint *portainer.EndpointSubset

	if len(p.settings.Endpoint) != 0 {
		for _, e := range endpoints {
			if *e.Name == p.settings.Endpoint {
				endpoint = &e
				break
			}
		}
	} else if len(endpoints) != 1 {
		return fmt.Errorf("ambigious endpoint")
	} else {
		endpoint = &endpoints[0]
	}

	if endpoint == nil {
		return fmt.Errorf("endpoint not found")
	}

	p.settings.endpointId = *endpoint.Id

	defer func() {
		if p.settings.docker != nil {
			p.settings.docker.Close()
		}
	}()

	swarmId, err := p.getSwarmId(ctx)
	if err != nil {
		return fmt.Errorf("error while getting swarm id: %w", err)
	}

	p.settings.swarmId = *swarmId

	if err = p.deployNetworks(ctx); err != nil {
		return fmt.Errorf("error while deploying networks: %w", err)
	}

	if err = p.deployConfigsPre(ctx); err != nil {
		return fmt.Errorf("error while deploying configs: %w", err)
	}

	if err = p.deployStack(ctx, client); err != nil {
		return fmt.Errorf("error while deploying stack: %w", err)
	}

	if err = p.deployConfigsPost(ctx); err != nil {
		return fmt.Errorf("error while deploying configs: %w", err)
	}

	return nil
}

func (p *Plugin) getDockerClient() (*client.Client, error) {
	if p.settings.docker != nil {
		return p.settings.docker, nil
	}

	portainerUrl, err := url.Parse(p.settings.Portainer)
	if err != nil {
		return nil, fmt.Errorf("error while parsing url: %w", err)
	}

	scheme := portainerUrl.Scheme

	portainerUrl.Scheme = "tcp"
	portainerUrl.Path = path.Join(portainerUrl.Path, "api", "endpoints", strconv.Itoa(int(p.settings.endpointId)), "docker")

	p.settings.docker, err = client.NewClientWithOpts(
		client.WithScheme(scheme),
		client.WithHost(portainerUrl.String()),
		client.WithHTTPHeaders(map[string]string{"Authorization": fmt.Sprintf("Bearer %s", p.settings.jwt)}),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating docker client: %w", err)
	}

	if p.settings.Insecure {
		p.settings.docker.HTTPClient().Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return p.settings.docker, nil
}

func (p *Plugin) getSwarmId(ctx context.Context) (*string, error) {
	docker, err := p.getDockerClient()
	if err != nil {
		return nil, fmt.Errorf("error while getting docker client: %w", err)
	}

	swarm, err := docker.SwarmInspect(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while inspecting swarm: %w", err)
	}

	return &swarm.ID, nil
}

func (p *Plugin) deployStack(ctx context.Context, client *portainer.APIClient) error {
	fmt.Printf("Deploying stack: %s\n", p.settings.Stack)

	filters, err := json.Marshal(map[string]string{"SwarmID": p.settings.swarmId})
	if err != nil {
		return fmt.Errorf("error while marshalling filters: %w", err)
	}

	stacks, _, err := client.StacksApi.StackList(ctx).
		Filters(string(filters)).
		Execute()
	if err != nil {
		return fmt.Errorf("error while retrieving stack list: %w", err)
	}

	var stack *portainer.Stack

	for _, s := range stacks {
		if *s.Name == p.settings.Stack {
			stack = &s
			break
		}
	}

	var env []portainer.StackEnv

	for key, value := range p.settings.environments {
		k := key
		v := fmt.Sprintf("%v", value)
		env = append(env, portainer.StackEnv{
			Name:  &k,
			Value: &v,
		})
	}

	if stack == nil {
		fmt.Printf("Creating stack: %s\n", p.settings.Stack)

		file, err := os.Open(p.settings.File)
		if err != nil {
			return fmt.Errorf("error while opening file: %w", err)
		}
		defer file.Close()

		env, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("error while marshalling environments: %w", err)
		}

		stack, _, err := client.StacksApi.StackCreate(ctx).
			Type_(1).
			Method("file").
			EndpointId(p.settings.endpointId).
			Name(p.settings.Stack).
			SwarmID(p.settings.swarmId).
			File(file).
			Env(string(env)).
			Execute()
		if err != nil {
			fmt.Println(string(err.(portainer.GenericOpenAPIError).Body()))
			return fmt.Errorf("error while creating stack: %w", err)
		}

		fmt.Printf("Created stack id=%d\n", *stack.Id)
	} else {
		fmt.Printf("Updating stack: %s\n", p.settings.Stack)

		if stack.Env != nil {
			for _, e := range *stack.Env {
				for _, c := range p.settings.configs {
					if c.Environment == *e.Name {
						if v, ok := p.settings.environments[*e.Name]; ok && v != *e.Value {
							p.settings.removeConfigs = append(p.settings.removeConfigs, *e.Value)
						}
					}
				}
			}
		}

		content, err := ioutil.ReadFile(p.settings.File)
		if err != nil {
			return fmt.Errorf("error while reading file: %w", err)
		}

		stackFileContent := string(content)
		prune := true

		stack, _, err := client.StacksApi.StackUpdate(ctx, *stack.Id).
			EndpointId(p.settings.endpointId).
			Body(portainer.StackUpdateRequest{
				StackFileContent: &stackFileContent,
				Env:              &env,
				Prune:            &prune,
			}).
			Execute()
		if err != nil {
			fmt.Println(string(err.(portainer.GenericOpenAPIError).Body()))
			return fmt.Errorf("error while updating stack: %w", err)
		}

		fmt.Printf("Updated stack id=%d\n", *stack.Id)
	}

	return nil
}

func (p *Plugin) deployNetworks(ctx context.Context) error {
	if len(p.settings.networks) == 0 {
		return nil
	}

	docker, err := p.getDockerClient()
	if err != nil {
		return fmt.Errorf("error while getting docker client: %w", err)
	}

	for name, network := range p.settings.networks {
		networks, err := docker.NetworkList(ctx, types.NetworkListOptions{
			Filters: filters.NewArgs(
				filters.Arg("name", name),
				filters.Arg("dangling", "true"),
			),
		})
		if err != nil {
			return fmt.Errorf("error while listing network: %w", err)
		}

		if len(networks) == 0 {
			fmt.Printf("Creating network: %s\n", name)

			options := make(map[string]string)
			if network.Encrypted {
				options["encrypted"] = strconv.FormatBool(network.Encrypted)
			}

			response, err := docker.NetworkCreate(ctx, name, types.NetworkCreate{
				Driver:  network.Driver,
				Options: options,
			})
			if err != nil {
				return fmt.Errorf("error while creating network: %w", err)
			}

			fmt.Printf("Network created=%s\n", response.ID)
		} else {
			fmt.Printf("Inspecting network: %s\n", name)

			response, err := docker.NetworkInspect(ctx, name, types.NetworkInspectOptions{})
			if err != nil {
				return fmt.Errorf("error while inspecting network: %w", err)
			}

			if response.Driver != network.Driver {
				return fmt.Errorf("network driver doesn't match")
			}

			if response.Options["encrypted"] != strconv.FormatBool(network.Encrypted) {
				return fmt.Errorf("network encryption doesn't match")
			}
		}
	}

	return nil
}

func (p *Plugin) deployConfigsPre(ctx context.Context) error {
	if len(p.settings.configs) == 0 {
		return nil
	}

	docker, err := p.getDockerClient()
	if err != nil {
		return fmt.Errorf("error while getting docker client: %w", err)
	}

	for name, config := range p.settings.configs {
		var data []byte

		if len(config.Data) != 0 {
			data = []byte(config.Data)
		} else {
			data, err = ioutil.ReadFile(config.File)
			if err != nil {
				return fmt.Errorf("error while reading file: %w", err)
			}
		}

		if len(config.Environment) != 0 {
			c := sha512.New()
			c.Write(data)
			c.Write([]byte(config.Template))
			checksum := hex.EncodeToString(c.Sum(nil))[:8]

			name = fmt.Sprintf("%s-%s", name, checksum)

			if p.settings.environments == nil {
				p.settings.environments = make(map[string]interface{})
			}
			p.settings.environments[config.Environment] = name
		}

		configs, err := docker.ConfigList(ctx, types.ConfigListOptions{
			Filters: filters.NewArgs(
				filters.Arg("name", name),
			),
		})
		if err != nil {
			return fmt.Errorf("error while listing configs: %w", err)
		}

		if len(configs) == 0 {
			fmt.Printf("Creating config: %s\n", name)

			var templating *swarm.Driver

			if len(config.Template) != 0 {
				templating = &swarm.Driver{
					Name: config.Template,
				}
			}

			response, err := docker.ConfigCreate(ctx, swarm.ConfigSpec{
				Annotations: swarm.Annotations{
					Name: name,
				},
				Data:       data,
				Templating: templating,
			})
			if err != nil {
				return fmt.Errorf("error while creating config: %w", err)
			}

			fmt.Printf("Config created=%s\n", response.ID)
		}
	}

	return nil
}

func (p *Plugin) deployConfigsPost(ctx context.Context) error {
	if len(p.settings.removeConfigs) == 0 {
		return nil
	}

	docker, err := p.getDockerClient()
	if err != nil {
		return fmt.Errorf("error while getting docker client: %w", err)
	}

	for _, name := range p.settings.removeConfigs {
		fmt.Printf("Removing config: %s\n", name)

		err := docker.ConfigRemove(ctx, name)
		if err != nil {
			return fmt.Errorf("error while removing config: %w", err)
		}

		fmt.Printf("Config removed=%s\n", name)
	}

	return nil
}
