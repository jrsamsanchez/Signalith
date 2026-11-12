# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# The Hetzner Cloud API token is read from the HCLOUD_TOKEN environment
# variable, never from a file in this folder.

variable "domain" {
  description = "The public name testers open. Its DNS A record must point at the server's address before HTTPS can start."
  type        = string
  default     = "lab.signalith.io"
}

variable "public" {
  description = "false: only admin_ip reaches port 443, while the lab is set up and checked. true: anyone does. Port 80 only redirects and answers Let's Encrypt, so it is always open."
  type        = bool
  default     = false
}

variable "admin_ip" {
  description = "The only address SSH (and, while public is false, the web page) is open to. Best given explicitly; empty: this computer's public IPv4 address, looked up when you run terraform (shown by the ssh_open_to output)."
  type        = string
  default     = ""

  validation {
    condition     = var.admin_ip == "" || can(regex("^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$", var.admin_ip))
    error_message = "admin_ip must be one IPv4 address, such as 203.0.113.7, without /32."
  }
}

variable "server_type" {
  description = "The Hetzner machine type: cx43 (8 cores, 16 GB) by default."
  type        = string
  default     = "cx43"
}

variable "volume_gb" {
  description = "The size of the volume OpenSearch keeps its data and snapshots on, in GB."
  type        = number
  default     = 100
}

variable "location" {
  description = "Hetzner location: nbg1, fsn1 or hel1."
  type        = string
  default     = "nbg1"
}

variable "ssh_key_name" {
  description = "The name of an SSH key already in the Hetzner project, put on the server for root."
  type        = string
  default     = "signalith-lab"
}

variable "admin_email" {
  description = "Let's Encrypt's contact address for the certificate, and where the lab's alerts go. Empty: no contact address."
  type        = string
  default     = ""
}
