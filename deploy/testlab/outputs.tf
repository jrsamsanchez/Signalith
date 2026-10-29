# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
output "dns_record" {
  description = "Add this A record where signalith.io's DNS is kept."
  value       = "${split(".", var.domain)[0]}  A  ${hcloud_server.testlab.ipv4_address}"
}

output "watch_setup" {
  description = "Shows the setup's progress. It ends with \"Test lab ready\"."
  value       = "ssh root@${hcloud_server.testlab.ipv4_address} tail -f /var/log/testlab-setup.log"
}

output "address" {
  description = "The server's public IPv4 address."
  value       = hcloud_server.testlab.ipv4_address
}

output "web_open_to" {
  description = "Who reaches the web page."
  value       = var.public ? "everyone" : local.admin_ip
}
