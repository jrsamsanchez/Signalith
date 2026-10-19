# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
output "signalith" {
  description = "Open this in your browser once the setup has finished."
  value       = "https://${hcloud_server.linux["signalith-1"].ipv4_address}:9000"
}

output "watch_setup" {
  description = "Shows the setup's progress on signalith-1. It ends with \"Lab ready\"."
  value       = "ssh root@${hcloud_server.linux["signalith-1"].ipv4_address} tail -f /var/log/lab-setup.log"
}

output "admin_password" {
  description = "Prints the admin password (user signalithadmin) the setup chose."
  value       = "ssh root@${hcloud_server.linux["signalith-1"].ipv4_address} cat /root/lab/admin-password"
}

output "machines" {
  description = "Each machine's public address, for ssh root@<address>."
  value = merge(
    { for k, s in hcloud_server.linux : k => s.ipv4_address },
    { for s in hcloud_server.windows : s.name => s.ipv4_address },
  )
}

output "allowed_in" {
  description = "The only address the firewall lets in."
  value       = local.home_ip
}
