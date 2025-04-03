#!/usr/bin/python3

import base64
import gzip
import http.client
import json
import os
import ssl
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class FileContents:
    inline: Optional[str] = None
    source: Optional[str] = None

@dataclass
class FileEntry:
    path: str
    overwrite: bool
    mode: int
    contents: FileContents

@dataclass
class SystemdUnit:
    name: str
    enabled: bool
    contents: Optional[str] = None

FILES_PLAIN: list[FileEntry] = [
  FileEntry(
    path="/etc/hostname",
    overwrite=True,
    mode=644,
    contents=FileContents(
      source="data:," + "{{.DPUHostName}}"
    )
  ),
  FileEntry(
    path="/etc/temp_bfcfg_strings.env",
    overwrite=True,
    mode=420,
    contents=FileContents(
      source="data:," + "bfb_pre_install%20bfb_modify_os%20bfb_post_install"
    )
  ),
  FileEntry(
    path="/usr/local/bin/dpf-ovs-script.sh",
    overwrite=True,
    mode=755,
    contents=FileContents(
      source="data:text/plain;charset=utf-8;base64," + "{{.OVSRawScript}}"
    )
  ),
  FileEntry(
    path="/etc/modules-load.d/br_netfilter.conf",
    overwrite=True,
    mode=420,
    contents=FileContents(
      source="data:," + "br_netfilter"
    )
  )
]

FILES: list[FileEntry] = [
  FileEntry(
    path="/etc/NetworkManager/system-connections/pf0vf0.nmconnection",
    overwrite=True,
    mode=600,
    contents=FileContents(
      inline="""[connection]
id=pf0vf0
type=ethernet
interface-name=pf0vf0
master=br-comm-ch
slave-type=bridge

[ethernet]
mtu=9000

[bridge-port]"""
    )
  ),
  FileEntry(
    path="/etc/NetworkManager/system-connections/br-comm-ch.nmconnection",
    overwrite=True,
    mode=600,
    contents=FileContents(
      inline="""[connection]
id=br-comm-ch
type=bridge
interface-name=br-comm-ch
autoconnect-ports=1
autoconnect-slaves=1

[bridge]
stp=false

[ipv4]
dhcp-client-id=mac
dhcp-timeout=2147483647
method=auto

[ipv6]
addr-gen-mode=eui64
dhcp-timeout=2147483647
method=disabled

[proxy]""")
  ),
  FileEntry(
    path="/etc/NetworkManager/system-connections/tmfifo_net0.nmconnection",
    overwrite=True,
    mode=600,
    contents=FileContents(
      inline="""[connection]
id=tmfifo_net0
type=ethernet
interface-name=tmfifo_net0
autoconnect=true

[ethernet]

[ipv4]
method=manual
address1=192.168.100.2/24
never-default=true

[ipv6]
method=ignore
""")
  ),
  FileEntry(
    path="/etc/sysctl.d/98-dpunet.conf",
    overwrite=True,
    mode=644,
    contents=FileContents(
      inline="""
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
"""
    )
  ),
  FileEntry(
    path="/usr/local/bin/dpf-configure-sfs.sh",
    overwrite=True,
    mode=644,
    contents=FileContents(
      inline="""#!/bin/bash
set -ex
CMD=$1
PF_TOTAL_SF=$2

case $CMD in
    setup) ;;
    *)
    echo "invalid first argument. ./configure-sfs.sh {setup}"
    exit 1
    ;;
esac

if [ "$CMD" = "setup" ]; then
    # Create SF on P0 for SFC
    # System SF(index 0) has been removed, so DPF will create SF from index 0
    for i in $(seq 0 $((PF_TOTAL_SF-1))); do
        /sbin/mlnx-sf --action create --device 0000:03:00.0 --sfnum ${i} || true
    done
fi
""")
  ),
  FileEntry(
    path="/usr/local/bin/set-nvconfig-params.sh",
    overwrite=True,
    mode=755,
    contents=FileContents(
      inline="""#!/bin/bash
set -e
for dev in /dev/mst/*; do
  echo "set NVConfig on dev ${dev}"
  mlxconfig -d ${dev} -y set $@
done
echo "Finished setting nvconfig parameters"
""")
  ),
]

SYSTEMD_UNITS: list[SystemdUnit] = [
  SystemdUnit(
    name="bfup-workaround.service",
    enabled=True,
    contents="""[Unit]
Description=Run bfup script 3 times with 2 minutes interval
After=network.target

[Service]
ExecStart=/bin/bash -c 'for i in {1..3}; do /usr/bin/bfup; sleep 400; done'
Type=oneshot
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
"""
  ),
  SystemdUnit(
    name="firstboot-dpf-ovs.service",
    enabled=True,
    contents="""[Unit]
Description=DPF OVS setup for first boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dpf-ovs-script.sh
RemainAfterExit=true
ConditionFirstBoot=true

[Install]
WantedBy=multi-user.target
"""),
  SystemdUnit(
    name="bootstrap-dpf.service",
    enabled=True,
    contents="""[Unit]
Description=Create Scalable Functions on the DPU required for DPF
After=network.target
Before=kubelet.service

[Service]
Type=oneshot
ExecStart=/bin/bash /usr/local/bin/dpf-configure-sfs.sh setup {{.SFNum}}

[Install]
WantedBy=multi-user.target"""
  ),
  SystemdUnit(
    name="set-nvconfig-params.service",
    enabled=True,
    contents="""[Unit]
Description=Set firmware properties
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/set-nvconfig-params.sh {{.NVConfigParams}}
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target"""
  )
]



def pull_ignition_file() -> bool:
  """
  Pulls the ignition file from the cluster and saves it as hcp.ign.
  Returns True if successful, False otherwise.
  """
  print("Pulling ignition file from cluster...")

  ignition_endpoint = subprocess.check_output(
      ["oc", "get", "hc", "-n", "clusters", "doca", "-o", "jsonpath={.status.ignitionEndpoint}"]
  ).decode('utf-8').strip()

  ignition_token_secrets: str = subprocess.check_output(
      ["oc", "-n", "clusters-doca", "get", "secret", "--no-headers", "-o", "custom-columns=NAME:.metadata.name"]
  ).decode('utf-8').strip()

  secrets: list[str] = [line for line in ignition_token_secrets.splitlines() if "token-doca" in line]
  if not secrets:
      print("Error: No token-doca secret found.")
      return False
  else:
      ignition_token_secret: str = secrets[0]

  ignition_token = subprocess.check_output(
     ["oc", "-n", "clusters-doca", "get", "secret", ignition_token_secret, "-o", "jsonpath={.data.token}"]
  ).decode('utf-8').strip()

  conn = http.client.HTTPSConnection(ignition_endpoint, context=ssl._create_unverified_context())
  conn.request("GET", "/ignition", headers={"Authorization": f"Bearer {ignition_token}"})

  res = conn.getresponse()
  if res.status != 200:
      print(f"Error: {res.status} {res.reason}")
      return False
  data = res.read()
  with open("hcp.ign", "wb") as f:
      f.write(data)
  
  print("Ignition file downloaded successfully.")
  return True

def preprocess_ignition_file(ign: dict) -> None:
  """
  Preprocesses the ignition file to disable the machine-config-daemon-firstboot.service
  and enable the openvswitch.service.
  """

  for s in ign['systemd']['units']:
    if s['name'] == 'machine-config-daemon-firstboot.service':
      s['enabled'] = False
    if s['name'] == 'openvswitch.service':
      s['enabled'] = True

def create_ignition_file() -> dict:
  """
  Creates a new ignition file with the required structure.
  """

  ign = {
    "ignition": {
      "version": "3.4.0"
    },
    "storage": {
      "files": []
    },
    "systemd": {
      "units": []
    }
  }

  return ign

def add_kernel_args(ign: dict) -> None:
  """
  Adds kernel arguments templating to the ignition file.
  """
  ign['kernelArguments'] = {
    'shouldExist': [
        "{{.KernelParameters}}"
      ]
  }
  
def add_files(ign: dict) -> None:
  """
  Adds files to the ignition file.
  """
  
  ign["ignition"]["version"] = "3.4.0"
  
  for file in FILES_PLAIN:
    ign['storage']['files'].append({
      'path': file.path,
      'overwrite': file.overwrite,
      'mode': file.mode,
      'contents': {
        'source': file.contents.source
      }
    })
    
  
  for file in FILES:
    ign['storage']['files'].append({
      'path': file.path,
      'overwrite': file.overwrite,
      'mode': file.mode,
      'contents': {
        'source': "data:text/plain;charset=utf-8;base64," + base64.b64encode(file.contents.inline.encode()).decode()
      }
    })

def add_systemd_units(ign: dict) -> None:
  """
  Adds systemd units to the ignition file.
  """

  for unit in SYSTEMD_UNITS:
    ign['systemd']['units'].append({
      'name': unit.name,
      'enabled': unit.enabled,
      'contents': unit.contents
    })

def write_template_ignition_file(ign: dict) -> None:
  """
  Writes the ignition file to disk.
  """

  ignition_template = json.dumps(ign, separators=(',', ':'))

# Indented json string
  yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-bfb.cfg
  namespace: dpf-operator-system
data:
    BF_CFG_TEMPLATE: |
        """ + ignition_template

  with open("hcp_template.ign", "w") as f:
    f.write(ignition_template)
    
  with open("hcp_template.yaml", "w") as f:
    f.write(yaml)
    
  print("Ignition file written to hcp_template.yaml")

def main():
  kubeconfig = os.environ.get('KUBECONFIG')
  if not kubeconfig:
    print("KUBECONFIG environment variable is not set.")
    return
  print(f"KUBECONFIG: {kubeconfig}")
  
  # Check if ignition file already exists
  if os.path.exists("hcp.ign"):
    print("Ignition file already exists. Skipping download.")
  else:
    pull_ignition_file()
    
  inner_ign: dict = json.load(open("hcp.ign"))
    
  preprocess_ignition_file(inner_ign)
  
  gzipped_ign = gzip.compress(json.dumps(inner_ign, separators=(',', ':')).encode('utf-8'))
  encoded_ign = base64.b64encode(gzipped_ign).decode()

  ign = create_ignition_file()
  
  ign['ignition']['config'] = {
    "merge": [
      {
        "compression": "gzip",
        "source": f"data:;base64,{encoded_ign}"
      }
    ]
  }

  add_kernel_args(ign)
  
  add_files(ign)
  
  add_systemd_units(ign)
  
  write_template_ignition_file(ign)
  

if __name__ == "__main__":
  main()