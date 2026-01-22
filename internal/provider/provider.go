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
	Host     types.String `tfsdk:"host"`
	Port     types.Int32  `tfsdk:"port"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
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
				Required:  true,
				Sensitive: true,
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
	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Unknown password",
			"Password must be set",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	host := config.Host.ValueString()
	port := uint(22)
	username := config.Username.ValueString()
	password := config.Password.ValueString()

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
	if password == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Missing password",
			"Password must be set",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := goph.NewConn(&goph.Config{
		Addr: host,
		Port: port,
		User: username,
		Auth: goph.Password(password),
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
