# Terraform Provider UFW

A Terraform provider for managing UFW (Uncomplicated Firewall) on remote Linux systems via SSH.

> [!CAUTION]
> This is a fun project and may break things!
> 
> This provider directly modifies firewall rules on your remote system. Use at your own risk, especially in production environments. Always test thoroughly in a non-critical environment first. Misconfigured firewall rules could lock you out of your server or expose it to security risks.

## Features

- Manage UFW firewall rules remotely via SSH
- Enable/disable UFW firewall
- Support for multiple rule actions: allow, deny, reject, limit
- Automatic drift detection
- Idempotent operations

## Requirements

- Terraform >= 1.0
- Go >= 1.24 (for development)
- Remote Linux system with UFW installed
- SSH access to the remote system
- Passwordless sudo access for UFW commands

## Installation

### From Terraform Registry

Add the provider to your Terraform configuration:

```hcl
terraform {
  required_providers {
    ufw = {
      source  = "simonprinz/ufw"
      version = "~> 1.0"
    }
  }
}
```

### Local Development Build

```bash
# Clone the repository
git clone https://github.com/SimonPrinz/terraform-provider-ufw.git
cd terraform-provider-ufw

# Build the provider
go build -o terraform-provider-ufw

# Install locally (optional)
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/simonprinz/ufw/1.0.0/darwin_arm64/
cp terraform-provider-ufw ~/.terraform.d/plugins/registry.terraform.io/simonprinz/ufw/1.0.0/darwin_arm64/
```

### Local Development with Dev Overrides

For local development, you can use Terraform's dev overrides feature:

```bash
# Build the provider
go build -o terraform-provider-ufw

# Create dev.tfrc
cat > dev.tfrc <<EOF
provider_installation {
    dev_overrides {
        "simonprinz/ufw" = "."
    }
    direct {}
}
EOF

# Use it with Terraform
export TF_CLI_CONFIG_FILE=$(pwd)/dev.tfrc
terraform init
terraform plan
```

## Provider Configuration

```hcl
provider "ufw" {
  host     = "192.168.1.100"  # Remote server IP or hostname
  port     = 22               # SSH port (optional, defaults to 22)
  username = "root"           # SSH username
  password = "your-password"  # SSH password (consider using environment variables)
}
```

### Configuration from Environment Variables

Store sensitive credentials in a `terraform.tfvars` file (add to `.gitignore`):

```hcl
# terraform.tfvars
host     = "192.168.1.100"
username = "root"
password = "your-secure-password"
```

## Resources

### ufw_rule

Manages individual UFW firewall rules.

#### Arguments

- `action` (Required) - Action to take on matching traffic. Valid values: `allow`, `deny`, `reject`, `limit`
- `protocol` (Optional) - Protocol to match. Valid values: `tcp`, `udp`, `any`. Defaults to `any`
- `port` (Optional) - Port number to match (1-65535)
- `comment` (Optional) - Human-readable comment for the rule

#### Attributes

- `id` - Computed unique identifier (hash of rule attributes)

#### Example Usage

```hcl
# Allow SSH access
resource "ufw_rule" "allow_ssh" {
  action   = "allow"
  protocol = "tcp"
  port     = 22
  comment  = "Allow SSH access"
}

# Allow HTTP traffic
resource "ufw_rule" "allow_http" {
  action   = "allow"
  protocol = "tcp"
  port     = 80
  comment  = "Allow HTTP"
}

# Allow HTTPS traffic
resource "ufw_rule" "allow_https" {
  action   = "allow"
  protocol = "tcp"
  port     = 443
  comment  = "Allow HTTPS"
}

# Deny telnet
resource "ufw_rule" "deny_telnet" {
  action = "deny"
  port   = 23
}

# Rate limit SSH (protection against brute force)
resource "ufw_rule" "limit_ssh" {
  action   = "limit"
  protocol = "tcp"
  port     = 22
  comment  = "Rate limit SSH"
}

# Allow all TCP traffic
resource "ufw_rule" "allow_tcp" {
  action   = "allow"
  protocol = "tcp"
  comment  = "Allow all TCP"
}
```

### ufw_status

Manages the UFW firewall enabled/disabled status. This is a singleton resource.

#### Arguments

- `enabled` (Required) - Whether UFW should be enabled (`true`) or disabled (`false`)

#### Attributes

- `id` - Computed static identifier

#### Example Usage

```hcl
# Enable UFW firewall
resource "ufw_status" "firewall" {
  enabled = true
}
```

**Important**: When this resource is destroyed (e.g., `terraform destroy`), the UFW status is NOT changed for safety. If you want to disable UFW before destroying, explicitly set `enabled = false` first.

## Complete Example

```hcl
terraform {
  required_providers {
    ufw = {
      source = "simonprinz/ufw"
    }
  }
}

provider "ufw" {
  host     = var.server_host
  username = var.ssh_username
  password = var.ssh_password
}

# Enable the firewall
resource "ufw_status" "firewall" {
  enabled = true
}

# Allow SSH (important - don't lock yourself out!)
resource "ufw_rule" "allow_ssh" {
  action   = "allow"
  protocol = "tcp"
  port     = 22
  comment  = "Allow SSH"
}

# Allow web traffic
resource "ufw_rule" "allow_http" {
  action   = "allow"
  protocol = "tcp"
  port     = 80
  comment  = "Allow HTTP"
}

resource "ufw_rule" "allow_https" {
  action   = "allow"
  protocol = "tcp"
  port     = 443
  comment  = "Allow HTTPS"
}

# Allow DNS
resource "ufw_rule" "allow_dns" {
  action   = "allow"
  protocol = "udp"
  port     = 53
  comment  = "Allow DNS"
}

# Deny FTP
resource "ufw_rule" "deny_ftp" {
  action   = "deny"
  protocol = "tcp"
  port     = 21
  comment  = "Block FTP"
}
```

## How It Works

### Rule Management

- **Create**: Executes `sudo ufw <action> <port>/<protocol> comment '<comment>'`
- **Read**: Parses `sudo ufw status numbered` to detect if rule exists (drift detection)
- **Update**: Deletes old rule and creates new one (UFW doesn't support in-place updates)
- **Delete**: Removes rule using `sudo ufw --force delete <rule_number>`

### Status Management

- **Create/Update**: Executes `sudo ufw --force enable` or `sudo ufw disable`
- **Read**: Parses `sudo ufw status` to detect current state
- **Delete**: Removes from Terraform state without changing UFW status (safety feature)

### Drift Detection

The provider automatically detects changes made outside Terraform:
- If a rule is deleted manually via SSH, Terraform will detect it during `terraform plan` and offer to recreate it
- If UFW is enabled/disabled outside Terraform, the status resource will detect the drift

## Limitations

- SSH password authentication only (key-based auth not yet implemented)
- Basic rule attributes only (no source/destination IPs, no interface specification)
- No support for importing existing rules
- Requires passwordless sudo for UFW commands
- IPv6 rules are created automatically by UFW but treated as the same resource

## Development

### Building

```bash
go build -o terraform-provider-ufw
```

### Testing

Create a test configuration:

```hcl
# test.tf
provider "ufw" {
  host     = "your-test-server"
  username = "root"
  password = "password"
}

resource "ufw_status" "test" {
  enabled = true
}

resource "ufw_rule" "test_ssh" {
  action   = "allow"
  protocol = "tcp"
  port     = 22
}
```

Run Terraform:

```bash
terraform plan
terraform apply
```

Verify on the remote server:

```bash
ssh root@your-test-server "sudo ufw status numbered"
```

## Security Considerations

1. **SSH Credentials**: Never commit credentials to version control. Use `terraform.tfvars` and add it to `.gitignore`
2. **SSH Access**: Ensure SSH access is locked down before enabling UFW
3. **Always Allow SSH**: Create an allow rule for port 22 before enabling UFW to avoid being locked out
4. **Sudo Access**: The SSH user needs passwordless sudo for UFW commands

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Simon Prinz

## Acknowledgments

- Built with [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework)
- SSH connectivity via [goph](https://github.com/melbahja/goph)
