# A Signalith test lab on Hetzner Cloud: see docs/cloud-lab.md.
#
#   terraform apply     builds it (signalith-1 then installs everything)
#   terraform destroy   deletes every machine, so nothing is billed

provider "hcloud" {}

data "http" "home_ip" {
  count = var.home_ip == "" ? 1 : 0
  url   = "https://ipv4.icanhazip.com"
}

locals {
  home_ip = var.home_ip != "" ? var.home_ip : chomp(data.http.home_ip[0].response_body)
  # The lab's private network. Only signalith-1's setup reaches the other
  # machines, with a key made for this lab.
  zone   = "eu-central"
  lb_ip  = "10.0.1.5"
  domain = "lab.internal"

  # Sized to fit a new Hetzner account's limits (20 shared cores, 10
  # public addresses): 9 machines, 20 cores, 9 addresses.
  all_machines = {
    "signalith-1"  = { role = "signalith", type = "cx23", ip = "10.0.1.11", minimal = true }
    "signalith-2"  = { role = "signalith", type = "cx23", ip = "10.0.1.12", minimal = false }
    "opensearch-1" = { role = "opensearch", type = "cx23", ip = "10.0.1.21", minimal = true }
    "opensearch-2" = { role = "opensearch", type = "cx23", ip = "10.0.1.22", minimal = false }
    "opensearch-3" = { role = "opensearch", type = "cx23", ip = "10.0.1.23", minimal = false }
    "scanner"      = { role = "scanner", type = "cx33", ip = "10.0.1.31", minimal = false }
    "sensor"       = { role = "sensor", type = "cx23", ip = "10.0.1.41", minimal = false }
    "linux-1"      = { role = "linux", type = "cx23", ip = "10.0.1.51", minimal = true }
  }
  linux_machines = { for k, v in local.all_machines : k => v if var.size == "full" || v.minimal }
  windows        = var.windows && var.size == "full"
  full           = var.size == "full"

  # Agents, the sensor and the joined servers send to this name: the load
  # balancer in the full lab, signalith-1 in the minimal one.
  siem_ip = local.full ? local.lb_ip : local.all_machines["signalith-1"].ip

  hosts = join("\n", concat(
    ["${local.siem_ip} siem.${local.domain}"],
    [for k, v in local.linux_machines : "${v.ip} ${k}.${local.domain} ${k}"],
    local.windows ? ["10.0.1.61 windows-1.${local.domain} windows-1"] : [],
  ))

  lab = {
    size     = var.size
    ref      = var.signalith_ref
    openvas  = var.openvas
    domain   = local.domain
    siem     = "siem.${local.domain}"
    lb_ip    = local.full ? local.lb_ip : ""
    machines = [for k, v in local.linux_machines : { name = k, role = v.role, ip = v.ip }]
  }
}

resource "tls_private_key" "lab" {
  algorithm = "ED25519"
}

resource "hcloud_ssh_key" "you" {
  name       = "signalith-lab"
  public_key = trimspace(file(pathexpand(var.ssh_public_key_file)))
}

resource "hcloud_network" "lab" {
  name     = "signalith-lab"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "lab" {
  network_id   = hcloud_network.lab.id
  type         = "cloud"
  network_zone = local.zone
  ip_range     = "10.0.1.0/24"
}

# Only your address gets in. The private network is not filtered: the
# machines reach each other there.
resource "hcloud_firewall" "lab" {
  name = "signalith-lab"
  rule {
    description = "SSH"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = ["${local.home_ip}/32"]
  }
  rule {
    description = "Signalith web page"
    direction   = "in"
    protocol    = "tcp"
    port        = "8080"
    source_ips  = ["${local.home_ip}/32"]
  }
  rule {
    description = "Windows remote desktop"
    direction   = "in"
    protocol    = "tcp"
    port        = "3389"
    source_ips  = ["${local.home_ip}/32"]
  }
  rule {
    description = "ping"
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["${local.home_ip}/32"]
  }
}

resource "hcloud_server" "linux" {
  for_each     = local.linux_machines
  name         = each.key
  server_type  = each.value.type
  image        = "ubuntu-24.04"
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.you.id]
  firewall_ids = [hcloud_firewall.lab.id]
  labels       = { lab = "signalith", role = each.value.role }

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    name      = each.key
    hosts     = local.hosts
    lab_key   = tls_private_key.lab.public_key_openssh
    conductor = each.key == "signalith-1"
    # Only signalith-1 gets the lab's private key, its settings and the
    # setup script.
    private_key = each.key == "signalith-1" ? tls_private_key.lab.private_key_openssh : ""
    lab_json    = each.key == "signalith-1" ? jsonencode(local.lab) : ""
    setup       = each.key == "signalith-1" ? base64gzip(replace(file("${path.module}/lab-setup.sh"), "\r\n", "\n")) : ""
  })

  network {
    network_id = hcloud_network.lab.id
    ip         = each.value.ip
  }
  public_net {
    ipv4_enabled = true
    ipv6_enabled = false
  }
  # A newer setup script must not rebuild machines that already run: it is
  # only used on their first boot.
  lifecycle {
    ignore_changes = [user_data]
  }
  depends_on = [hcloud_network_subnet.lab]
}

# Windows is installed from the Hetzner Console (docs/cloud-lab.md), or
# comes from a snapshot of an earlier install.
resource "hcloud_server" "windows" {
  count        = local.windows ? 1 : 0
  name         = "windows-1"
  server_type  = "cx23"
  image        = var.windows_image != "" ? var.windows_image : "ubuntu-24.04"
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.you.id]
  firewall_ids = [hcloud_firewall.lab.id]
  labels       = { lab = "signalith", role = "windows" }

  network {
    network_id = hcloud_network.lab.id
    ip         = "10.0.1.61"
  }
  public_net {
    ipv4_enabled = true
    ipv6_enabled = false
  }
  depends_on = [hcloud_network_subnet.lab]
}

# The load balancer has no public address: agents, the sensor and the
# servers reach it on the private network only.
resource "hcloud_load_balancer" "lab" {
  count              = local.full ? 1 : 0
  name               = "signalith-lab"
  load_balancer_type = "lb11"
  location           = var.location
}

resource "hcloud_load_balancer_network" "lab" {
  count                   = local.full ? 1 : 0
  load_balancer_id        = hcloud_load_balancer.lab[0].id
  network_id              = hcloud_network.lab.id
  ip                      = local.lb_ip
  enable_public_interface = false
  depends_on              = [hcloud_network_subnet.lab]
}

resource "hcloud_load_balancer_service" "web" {
  count            = local.full ? 1 : 0
  load_balancer_id = hcloud_load_balancer.lab[0].id
  protocol         = "tcp"
  listen_port      = 8080
  destination_port = 8080
  proxyprotocol    = true
  health_check {
    protocol = "http"
    port     = 8080
    interval = 10
    timeout  = 5
    retries  = 3
    http {
      path         = "/readyz"
      tls          = true
      status_codes = ["200"]
    }
  }
}

resource "hcloud_load_balancer_target" "servers" {
  for_each         = local.full ? toset(["signalith-1", "signalith-2"]) : toset([])
  type             = "server"
  load_balancer_id = hcloud_load_balancer.lab[0].id
  server_id        = hcloud_server.linux[each.key].id
  use_private_ip   = true
  depends_on       = [hcloud_load_balancer_network.lab]
}
