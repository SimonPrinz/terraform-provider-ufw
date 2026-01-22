package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/melbahja/goph"
)

var (
	_ resource.Resource              = &RuleResource{}
	_ resource.ResourceWithConfigure = &RuleResource{}
)

func NewRuleResource() resource.Resource {
	return &RuleResource{}
}

type RuleResource struct {
	client *goph.Client
}

type RuleResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Action   types.String `tfsdk:"action"`
	Protocol types.String `tfsdk:"protocol"`
	Port     types.Int64  `tfsdk:"port"`
	Comment  types.String `tfsdk:"comment"`
}

func (r *RuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *RuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rule"
}

func (r *RuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a UFW firewall rule on a remote Linux system via SSH.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Computed identifier for the rule (hash of rule attributes).",
			},
			"action": schema.StringAttribute{
				Required:    true,
				Description: "Action to take: allow, deny, reject, or limit.",
				Validators: []validator.String{
					stringvalidator.OneOf("allow", "deny", "reject", "limit"),
				},
			},
			"protocol": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("any"),
				Description: "Protocol: tcp, udp, or any. Defaults to 'any'.",
				Validators: []validator.String{
					stringvalidator.OneOf("tcp", "udp", "any"),
				},
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Description: "Port number (1-65535).",
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "Human-readable comment for the rule.",
			},
		},
	}
}

func (r *RuleResource) buildUFWCommand(plan RuleResourceModel) string {
	var cmd strings.Builder

	cmd.WriteString("sudo ufw ")
	cmd.WriteString(plan.Action.ValueString())

	if !plan.Port.IsNull() {
		cmd.WriteString(" ")
		protocol := plan.Protocol.ValueString()
		if protocol == "any" {
			protocol = "tcp"
		}
		cmd.WriteString(strconv.FormatInt(plan.Port.ValueInt64(), 10))
		cmd.WriteString("/")
		cmd.WriteString(protocol)
	} else if !plan.Protocol.IsNull() && plan.Protocol.ValueString() != "any" {
		cmd.WriteString(" proto ")
		cmd.WriteString(plan.Protocol.ValueString())
	}

	if !plan.Comment.IsNull() && plan.Comment.ValueString() != "" {
		cmd.WriteString(" comment '")
		comment := strings.ReplaceAll(plan.Comment.ValueString(), "'", "'\\''")
		cmd.WriteString(comment)
		cmd.WriteString("'")
	}

	return cmd.String()
}

func (r *RuleResource) executeSSHCommand(ctx context.Context, command string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("SSH client not configured")
	}

	tflog.Debug(ctx, "Executing SSH command", map[string]any{
		"command": command,
	})

	out, err := r.client.Run(command)
	if err != nil {
		tflog.Error(ctx, "SSH command failed", map[string]any{
			"command": command,
			"error":   err.Error(),
			"output":  string(out),
		})
		return string(out), fmt.Errorf("SSH command failed: %w (output: %s)", err, string(out))
	}

	output := string(out)
	tflog.Debug(ctx, "SSH command succeeded", map[string]any{
		"command": command,
		"output":  output,
	})

	return output, nil
}

func (r *RuleResource) generateRuleID(plan RuleResourceModel) string {
	h := sha256.New()

	h.Write([]byte(plan.Action.ValueString()))
	h.Write([]byte(plan.Protocol.ValueString()))

	if !plan.Port.IsNull() {
		h.Write([]byte(strconv.FormatInt(plan.Port.ValueInt64(), 10)))
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (r *RuleResource) findRuleInStatus(ctx context.Context, plan RuleResourceModel) (int64, bool) {
	output, err := r.executeSSHCommand(ctx, "sudo ufw status numbered")
	if err != nil {
		tflog.Warn(ctx, "Failed to get UFW status", map[string]any{
			"error": err.Error(),
		})
		return 0, false
	}

	lines := strings.Split(output, "\n")
	action := strings.ToUpper(plan.Action.ValueString())
	protocol := strings.ToUpper(plan.Protocol.ValueString())

	for _, line := range lines {
		if !strings.HasPrefix(line, "[") {
			continue
		}

		var ruleNum int64
		if _, err := fmt.Sscanf(line, "[ %d]", &ruleNum); err != nil {
			continue
		}

		lineUpper := strings.ToUpper(line)

		if !strings.Contains(lineUpper, action) {
			continue
		}

		if !plan.Port.IsNull() {
			portStr := strconv.FormatInt(plan.Port.ValueInt64(), 10)
			if !strings.Contains(line, portStr) {
				continue
			}
		}

		if protocol != "ANY" {
			if !strings.Contains(lineUpper, protocol) {
				continue
			}
		}

		return ruleNum, true
	}

	return 0, false
}

func (r *RuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ufwCmd := r.buildUFWCommand(plan)

	tflog.Info(ctx, "Creating UFW rule", map[string]any{
		"command": ufwCmd,
	})

	output, err := r.executeSSHCommand(ctx, ufwCmd)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create UFW rule",
			fmt.Sprintf("Could not execute UFW command: %s\nOutput: %s\nError: %s",
				ufwCmd, output, err.Error()),
		)
		return
	}

	if !strings.Contains(output, "Rule added") && !strings.Contains(output, "Skipping") {
		resp.Diagnostics.AddWarning(
			"Unexpected UFW output",
			fmt.Sprintf("UFW command executed but got unexpected output: %s", output),
		)
	}

	plan.ID = types.StringValue(r.generateRuleID(plan))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *RuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading UFW rule", map[string]any{
		"id": state.ID.ValueString(),
	})

	_, found := r.findRuleInStatus(ctx, state)
	if !found {
		tflog.Warn(ctx, "UFW rule not found, removing from state", map[string]any{
			"id": state.ID.ValueString(),
		})
		resp.State.RemoveResource(ctx)
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state RuleResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating UFW rule", map[string]any{
		"id": state.ID.ValueString(),
	})

	ruleNum, found := r.findRuleInStatus(ctx, state)
	if found {
		deleteCmd := fmt.Sprintf("sudo ufw --force delete %d", ruleNum)
		_, err := r.executeSSHCommand(ctx, deleteCmd)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to delete old UFW rule",
				fmt.Sprintf("Could not delete rule %d: %s", ruleNum, err.Error()),
			)
			return
		}
	} else {
		tflog.Warn(ctx, "Old rule not found during update, proceeding to create new rule", map[string]any{
			"id": state.ID.ValueString(),
		})
	}

	ufwCmd := r.buildUFWCommand(plan)
	output, err := r.executeSSHCommand(ctx, ufwCmd)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create updated UFW rule",
			fmt.Sprintf("Could not execute UFW command: %s\nError: %s", ufwCmd, err.Error()),
		)
		return
	}

	if !strings.Contains(output, "Rule added") && !strings.Contains(output, "Skipping") {
		resp.Diagnostics.AddWarning(
			"Unexpected UFW output",
			fmt.Sprintf("UFW command executed but got unexpected output: %s", output),
		)
	}

	plan.ID = types.StringValue(r.generateRuleID(plan))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting UFW rule", map[string]any{
		"id": state.ID.ValueString(),
	})

	ruleNum, found := r.findRuleInStatus(ctx, state)
	if !found {
		tflog.Warn(ctx, "UFW rule not found, considering already deleted", map[string]any{
			"id": state.ID.ValueString(),
		})
		return
	}

	deleteCmd := fmt.Sprintf("sudo ufw --force delete %d", ruleNum)
	output, err := r.executeSSHCommand(ctx, deleteCmd)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete UFW rule",
			fmt.Sprintf("Could not delete rule %d: %s\nOutput: %s", ruleNum, err.Error(), output),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted UFW rule", map[string]any{
		"rule_number": ruleNum,
	})
}
