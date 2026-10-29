# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# The public test lab at lab.signalith.io: one long-lived server that
# outside testers sign into (see README.md). Unlike deploy/lab, it is not
# deleted between sessions, and it runs released packages, not builds.
#
#   terraform apply                   builds it (testlab-setup runs on first boot)
#   terraform apply -var public=true  opens port 443 to everyone, after the checks

provider "hcloud" {}

data "http" "admin_ip" {
  count = var.admin_ip == "" ? 1 : 0
  url   = "https://ipv4.icanhazip.com"
}

data "hcloud_ssh_key" "admin" {
  name = var.ssh_key_name
}

locals {
  admin_ip = var.admin_ip != "" ? var.admin_ip : chomp(data.http.admin_ip[0].response_body)
  web_from = var.public ? ["0.0.0.0/0", "::/0"] : ["${local.admin_ip}/32"]
  settings = {
    domain      = var.domain
    admin_email = var.admin_email
  }
}

# Everything else is refused: Signalith, its agent port and OpenSearch
# listen on 127.0.0.1 only, behind Caddy.
resource "hcloud_firewall" "testlab" {
  name = "signalith-testlab"
  rule {
    description = "HTTPS"
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = local.web_from
  }
  rule {
    description = "HTTP: redirects to HTTPS and answers Let's Encrypt"
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = local.web_from
  }
  rule {
    description = "SSH, from the admin only"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = ["${local.admin_ip}/32"]
  }
}

resource "hcloud_server" "testlab" {
  name         = "signalith-testlab"
  server_type  = var.server_type
  image        = "ubuntu-24.04"
  location     = var.location
  ssh_keys     = [data.hcloud_ssh_key.admin.id]
  firewall_ids = [hcloud_firewall.testlab.id]
  backups      = true
  labels       = { lab = "signalith-testlab" }

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    settings = jsonencode(local.settings)
    setup    = base64gzip(replace(file("${path.module}/testlab-setup.sh"), "\r\n", "\n"))
  })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
  # The setup only runs on the first boot: a newer script must not rebuild
  # the server testers use.
  lifecycle {
    ignore_changes  = [user_data]
    prevent_destroy = true
  }
}

# OpenSearch's data and the local snapshots, apart from the system disk.
resource "hcloud_volume" "data" {
  name      = "signalith-testlab-data"
  size      = var.volume_gb
  server_id = hcloud_server.testlab.id
  format    = "ext4"
  automount = false
  labels    = { lab = "signalith-testlab" }
  lifecycle {
    prevent_destroy = true
  }
}
