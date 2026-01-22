terraform {
  required_providers {
    ufw = {
      source = "simonprinz/ufw"
    }
  }
}

variable "host" {
  type = string
}
variable "username" {
  type = string
}
variable "password" {
  type      = string
  sensitive = true
}

provider "ufw" {
  host     = var.host
  username = var.username
  password = var.password
}

resource "ufw_status" "status" {
  enabled = true
}

resource "ufw_rule" "allow_ssh" {
  action = "allow"
  protocol = "tcp"
  port = 22
  comment = "Allow SSH"

  # enable ufw only when ssh is allowed
  depends_on = [ufw_status.status]
}

# resource "ufw_rule" "allow_http" {
#   action = "allow"
#   protocol = "tcp"
#   port = 80
#   comment = "Allow HTTP"
# }

# resource "ufw_rule" "allow_https" {
#   action = "allow"
#   protocol = "tcp"
#   port = 443
#   comment = "Allow HTTPS"
# }
