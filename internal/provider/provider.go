package provider

import (
	"context"
	"log"
	"net"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

var (
	_ provider.Provider = &UfwProvider{}
)

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UfwProvider{
			version: version,
		}
	}
}

type UfwProvider struct {
	version string
	client  *goph.Client
}

type UfwProviderModel struct {
	Host               types.String `tfsdk:"host"`
	Port               types.Int32  `tfsdk:"port"`
	Username           types.String `tfsdk:"username"`
	Password           types.String `tfsdk:"password"`
	PrivateKey         types.String `tfsdk:"private_key"`
	PrivateKeyFile     types.String `tfsdk:"private_key_file"`
	PrivateKeyPassword types.String `tfsdk:"private_key_password"`
	UseSshAgent        types.Bool   `tfsdk:"use_ssh_agent"`
}

func (p *UfwProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ufw"
	resp.Version = p.version
}

func (p *UfwProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Host Url",
			},
			"port": schema.Int32Attribute{
				Required: false,
				Optional: true,
			},
			"username": schema.StringAttribute{
				Required: true,
			},
			"password": schema.StringAttribute{
				Required:  false,
				Optional:  true,
				Sensitive: true,
			},
			"private_key": schema.StringAttribute{
				Required:  false,
				Optional:  true,
				Sensitive: true,
			},
			"private_key_file": schema.StringAttribute{
				Required: false,
				Optional: true,
			},
			"private_key_password": schema.StringAttribute{
				Required:  false,
				Optional:  true,
				Sensitive: true,
			},
			"use_ssh_agent": schema.BoolAttribute{
				Required: false,
				Optional: true,
			},
		},
	}
}

func (p *UfwProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config UfwProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Host.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"Unknown host",
			"Host must be set",
		)
	}
	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown username",
			"Username must be set",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	host := config.Host.ValueString()
	port := uint(22)
	username := config.Username.ValueString()

	if !config.Port.IsNull() {
		port = uint(config.Port.ValueInt32())
	}

	if host == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"Missing Host",
			"Host must be set",
		)
	}
	if username == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Missing username",
			"Username must be set",
		)
	}

	var auth []ssh.AuthMethod
	if !config.Password.IsUnknown() && !config.Password.IsNull() {
		auth = append(auth, goph.Password(config.Password.ValueString())...)
	}
	if !config.PrivateKey.IsUnknown() && !config.PrivateKey.IsNull() {
		privateKeyPassword := ""
		if !config.PrivateKeyPassword.IsUnknown() {
			privateKeyPassword = config.PrivateKeyPassword.ValueString()
		}
		key, err := goph.RawKey(config.PrivateKey.ValueString(), privateKeyPassword)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("private_key"),
				"Error reading private key",
				err.Error(),
			)
		}
		auth = append(auth, key...)
	}
	if !config.PrivateKeyFile.IsUnknown() && !config.PrivateKeyFile.IsNull() {
		privateKeyPassword := ""
		if !config.PrivateKeyPassword.IsUnknown() {
			privateKeyPassword = config.PrivateKeyPassword.ValueString()
		}
		key, err := goph.Key(config.PrivateKeyFile.ValueString(), privateKeyPassword)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("private_key_file"),
				"Error reading private key file",
				err.Error(),
			)
		}
		auth = append(auth, key...)
	}
	if !config.UseSshAgent.IsUnknown() && config.UseSshAgent.ValueBool() {
		agent, err := goph.UseAgent()
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("use_ssh_agent"),
				"Error reading ssh agent",
				err.Error(),
			)
		}
		auth = append(auth, agent...)
	}

	if len(auth) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Empty(),
			"Missing Auth Method",
			"An auth method must be set",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := goph.NewConn(&goph.Config{
		Addr: host,
		Port: port,
		User: username,
		Auth: auth,
		Callback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	p.client = client
	resp.ResourceData = client
}

func (p *UfwProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRuleResource,
		NewStatusResource,
	}
}

func (p *UfwProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
