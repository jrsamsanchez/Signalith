# Cloud test lab

Terraform files that build a Signalith test lab on Hetzner Cloud, and the script
signalith-1 runs to set the rest up. How to use them, and what they cost:
[docs/cloud-lab.md](https://github.com/jrsamsanchez/Signalith/blob/main/docs/cloud-lab.md).

| File | What |
| --- | --- |
| `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf` | The machines, network, firewall and load balancer |
| `cloud-init.yaml.tftpl` | First boot of each Linux machine |
| `lab-setup.sh` | Run on signalith-1: OpenSearch, Signalith, joins, OpenVAS, agents, the sensor |
