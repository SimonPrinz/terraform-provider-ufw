package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/melbahja/goph"
)

var (
	_ resource.Resource              = &StatusResource{}
	_ resource.ResourceWithConfigure = &StatusResource{}
)

func NewStatusResource() resource.Resource {
	return &StatusResource{}
}

type StatusResource struct {
	client *goph.Client
}

type StatusResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func (r *StatusResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*goph.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *goph.Client, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *StatusResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_status"
}

func (r *StatusResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the UFW firewall enabled/disabled status on a remote Linux system via SSH.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Static identifier for the UFW status resource.",
			},
			"enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether UFW firewall should be enabled (true) or disabled (false).",
			},
		},
	}
}

func (r *StatusResource) executeSSHCommand(ctx context.Context, command string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("SSH client not configured")
	}

	tflog.Debug(ctx, "Executing SSH command", map[string]any{
		"command": command,
	})

	out, err := r.client.Run(command)
	output := string(out)

	if err != nil {
		tflog.Error(ctx, "SSH command failed", map[string]any{
			"command": command,
			"error":   err.Error(),
			"output":  output,
		})
		return output, fmt.Errorf("SSH command failed: %w (output: %s)", err, output)
	}

	tflog.Debug(ctx, "SSH command succeeded", map[string]any{
		"command": command,
		"output":  output,
	})

	return output, nil
}

func (r *StatusResource) isUFWEnabled(ctx context.Context) (bool, error) {
	output, err := r.executeSSHCommand(ctx, "sudo ufw status")
	if err != nil {
		return false, err
	}

	if strings.Contains(strings.ToLower(output), "status: active") {
		return true, nil
	}
	if strings.Contains(strings.ToLower(output), "status: inactive") {
		return false, nil
	}

	return false, fmt.Errorf("unable to parse UFW status from output: %s", output)
}

func (r *StatusResource) setUFWStatus(ctx context.Context, enabled bool) error {
	var cmd string
	if enabled {
		cmd = "sudo ufw --force enable"
	} else {
		cmd = "sudo ufw disable"
	}

	output, err := r.executeSSHCommand(ctx, cmd)
	if err != nil {
		return err
	}

	if enabled {
		if !strings.Contains(strings.ToLower(output), "firewall is active") {
			return fmt.Errorf("unexpected output when enabling UFW: %s", output)
		}
	} else {
		if !strings.Contains(strings.ToLower(output), "firewall stopped") {
			tflog.Warn(ctx, "Unexpected output when disabling UFW", map[string]any{
				"output": output,
			})
		}
	}

	return nil
}

func (r *StatusResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan StatusResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enabled := plan.Enabled.ValueBool()

	tflog.Info(ctx, "Setting UFW status", map[string]any{
		"enabled": enabled,
	})

	err := r.setUFWStatus(ctx, enabled)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to set UFW status",
			fmt.Sprintf("Could not %s UFW: %s", map[bool]string{true: "enable", false: "disable"}[enabled], err.Error()),
		)
		return
	}

	plan.ID = types.StringValue("ufw-status")

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *StatusResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state StatusResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading UFW status", map[string]any{
		"id": state.ID.ValueString(),
	})

	enabled, err := r.isUFWEnabled(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read UFW status",
			fmt.Sprintf("Could not read UFW status: %s", err.Error()),
		)
		return
	}

	state.Enabled = types.BoolValue(enabled)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *StatusResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan StatusResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state StatusResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enabled := plan.Enabled.ValueBool()

	tflog.Info(ctx, "Updating UFW status", map[string]any{
		"enabled": enabled,
	})

	err := r.setUFWStatus(ctx, enabled)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update UFW status",
			fmt.Sprintf("Could not %s UFW: %s", map[bool]string{true: "enable", false: "disable"}[enabled], err.Error()),
		)
		return
	}

	state.Enabled = plan.Enabled

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *StatusResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state StatusResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting UFW status resource", map[string]any{
		"id": state.ID.ValueString(),
	})

	tflog.Info(ctx, "UFW status resource removed from state (firewall status unchanged)")
}
