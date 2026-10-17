# The Hetzner Cloud API token is read from the HCLOUD_TOKEN environment
# variable, never from a file in this folder.

variable "size" {
  description = "full: every machine (about $0.10 an hour). minimal: one Signalith server, one OpenSearch node and one Linux endpoint (about $0.03 an hour). loadtest: the terabyte-a-day load test's machines (about $0.12 an hour with one Signalith server; see docs/cloud-lab.md)."
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

variable "loadtest_servers" {
  description = "How many Signalith servers the load test has (1 to 3): signalith-2 and signalith-3 join signalith-1, so detections can be spread over them (sudo lab-loadtest spread). With 2 or 3, use loadtest_opensearch_type = cx33 unless the account's core limit was raised."
  type        = number
  default     = 1
  validation {
    condition     = var.loadtest_servers >= 1 && var.loadtest_servers <= 3 && floor(var.loadtest_servers) == var.loadtest_servers
    error_message = "loadtest_servers is 1, 2 or 3."
  }
}

variable "loadtest_opensearch_type" {
  description = "The Hetzner machine type of the load test's two OpenSearch nodes: cx43 (8 cores, 16 GB), or cx33 (4 cores, 8 GB) to fit two or three Signalith servers in 20 cores."
  type        = string
  default     = "cx43"
  validation {
    condition     = contains(["cx23", "cx33", "cx43", "cx53"], var.loadtest_opensearch_type)
    error_message = "loadtest_opensearch_type is cx23, cx33, cx43 or cx53."
  }
}

variable "vcpu_limit" {
  description = "The most cores the Hetzner account may have (20 on a new account). The load test's machines must fit in it; raise it once Hetzner has raised the limit."
  type        = number
  default     = 20
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

variable "opensearch_version" {
  description = "The OpenSearch version the lab installs. Defaults to the version the Docker quick start and Helm chart use; set 2.17.1 to test upgrades from OpenSearch 2."
  type        = string
  default     = "3.9.0"
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
