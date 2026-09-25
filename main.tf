terraform {
  required_providers {
    ufw = {
      source = "simonprinz/ufw"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "4.1.0"
    }
  }
}

provider "ufw" {
  alias = "password"

  host     = "ufw.orb.local"
  username = "simon"
  password = "simon"
}
resource "ufw_status" "status" {
  provider = ufw.password

  enabled = true

  # enable ufw only when ssh is allowed
  depends_on = [ufw_rule.allow_ssh]
}
resource "ufw_rule" "allow_ssh" {
  provider = ufw.password

  action   = "allow"
  protocol = "tcp"
  port     = 22
  comment  = "Allow SSH"
}

resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits = 2048
}
provider "ufw" {
  alias = "private_key"

  host     = "ufw.orb.local"
  username = "simon"
  private_key = tls_private_key.ssh_key.private_key_pem
}
resource "ufw_rule" "allow_http" {
  provider = ufw.private_key

  action = "allow"
  protocol = "tcp"
  port = 80
  comment = "Allow HTTP"
}

provider "ufw" {
  alias = "use_ssh_agent"

  host     = "ufw.orb.local"
  username = "simon"
  use_ssh_agent = true
}
resource "ufw_rule" "allow_https" {
  provider = ufw.use_ssh_agent

  action = "allow"
  protocol = "tcp"
  port = 443
  comment = "Allow HTTPS"
}
