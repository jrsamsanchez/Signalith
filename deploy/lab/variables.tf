# The Hetzner Cloud API token is read from the HCLOUD_TOKEN environment
# variable, never from a file in this folder.

variable "size" {
  description = "full: every machine (about $0.10 an hour). minimal: one Signalith server, one OpenSearch node and one Linux endpoint (about $0.03 an hour). loadtest: the terabyte-a-day load test's machines (about $0.12 an hour; see docs/cloud-lab.md)."
  type        = string
  default     = "full"
  validation {
    condition     = contains(["full", "minimal", "loadtest"], var.size)
    error_message = "size is full, minimal or loadtest."
  }
}

variable "loadtest_volume_gb" {
  description = "The size of each OpenSearch node's volume in the load test, in GB."
  type        = number
  default     = 500
}

variable "location" {
  description = "Hetzner location: nbg1 (Nuremberg), fsn1 (Falkenstein) or hel1 (Helsinki). The cheap CX machines are only offered there."
  type        = string
  default     = "nbg1"
}

variable "home_ip" {
  description = "The only address allowed in (SSH, the web page, Windows remote desktop). Empty: this computer's public IPv4 address, looked up when you run terraform."
  type        = string
  default     = ""
}

variable "ssh_public_key_file" {
  description = "Your SSH public key, put on every Linux machine for root."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "signalith_ref" {
  description = "The Signalith branch, tag or commit to build and install."
  type        = string
  default     = "main"
}

variable "windows" {
  description = "Make windows-1, a machine you install Windows Server on from the Hetzner Console (full lab only)."
  type        = bool
  default     = true
}

variable "windows_image" {
  description = "A snapshot of windows-1 saved after installing Windows once, so it needs no installing next time. Empty: start from a blank disk."
  type        = string
  default     = ""
}

variable "openvas" {
  description = "Install OpenVAS (Greenbone Community Edition) on the scanner. Its feed download takes an hour or more."
  type        = bool
  default     = true
}
