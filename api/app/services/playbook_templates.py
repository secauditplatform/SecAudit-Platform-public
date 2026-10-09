from pathlib import Path

from secaudit_core.connectivity_playbook import CONNECTIVITY_CHECK_CONTENT

_CONTENT_DIR = Path(__file__).resolve().parent / "playbook_content"


def _load_playbook_content(name: str) -> str:
    return (_CONTENT_DIR / name).read_text(encoding="utf-8")


PLAYBOOK_TEMPLATES: list[dict[str, str]] = [
    {
        "id": "linux-inventory",
        "name": "Linux inventory",
        "description": "Collect OS facts, packages, services, and listening ports on Linux hosts",
        "category": "inventory",
        "content": """---
- name: Linux host inventory
  hosts: all
  gather_facts: true
  tasks:
    - name: Identity and uptime
      ansible.builtin.shell: |
        set -o pipefail
        whoami
        id
        uptime -p || uptime
      register: identity_uptime
      changed_when: false
      failed_when: false

    - name: Local users (system database)
      ansible.builtin.shell: |
        getent passwd | awk -F: '{print $1 ":" $3 ":" $7}' | head -n 80
      register: local_users
      changed_when: false
      failed_when: false

    - name: Recent login activity
      ansible.builtin.shell: |
        last -n 20 || true
      register: recent_logins
      changed_when: false
      failed_when: false

    - name: Package facts
      ansible.builtin.package_facts:
        manager: auto
      ignore_errors: true

    - name: Service facts
      ansible.builtin.service_facts:

    - name: Running services (top 60)
      ansible.builtin.shell: |
        systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null | head -n 60
      register: running_services_text
      changed_when: false
      failed_when: false

    - name: Listening ports
      ansible.builtin.shell: |
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
      register: listening_ports
      changed_when: false
      ignore_errors: true

    - name: Firewall rules (nftables/iptables)
      ansible.builtin.shell: |
        if command -v nft >/dev/null 2>&1; then
          nft list ruleset | sed -n '1,120p'
        elif command -v iptables >/dev/null 2>&1; then
          iptables -S | sed -n '1,120p'
        else
          echo "No nft/iptables detected"
        fi
      register: firewall_rules
      changed_when: false
      failed_when: false

    - name: Security logs sample
      ansible.builtin.shell: |
        if [ -f /var/log/auth.log ]; then
          tail -n 40 /var/log/auth.log
        elif [ -f /var/log/secure ]; then
          tail -n 40 /var/log/secure
        else
          journalctl -n 40 -p warning --no-pager 2>/dev/null || echo "Security log unavailable"
        fi
      register: security_logs
      changed_when: false
      failed_when: false

    - name: Inventory summary
      ansible.builtin.debug:
        msg:
          hostname: "{{ ansible_hostname }}"
          fqdn: "{{ ansible_fqdn }}"
          os: "{{ ansible_distribution }} {{ ansible_distribution_version }}"
          kernel: "{{ ansible_kernel }}"
          architecture: "{{ ansible_architecture }}"
          ipv4: "{{ ansible_all_ipv4_addresses }}"
          identity_uptime: "{{ identity_uptime.stdout_lines | default([]) }}"
          local_users: "{{ local_users.stdout_lines | default([]) }}"
          recent_logins: "{{ recent_logins.stdout_lines | default([]) }}"
          packages_count: "{{ ansible_facts.packages | default({}) | length }}"
          services: "{{ ansible_facts.services | default({}) | dict2items | selectattr('value.state', 'equalto', 'running') | map(attribute='key') | list }}"
          running_services_text: "{{ running_services_text.stdout_lines | default([]) }}"
          listening_ports: "{{ listening_ports.stdout_lines | default([]) }}"
          firewall_rules: "{{ firewall_rules.stdout_lines | default([]) }}"
          security_logs: "{{ security_logs.stdout_lines | default([]) }}"
""",
        "content_fast": """---
- name: Linux host inventory (fast)
  hosts: all
  gather_facts: true
  tasks:
    - name: Identity and uptime
      ansible.builtin.shell: |
        whoami
        id
        uptime -p || uptime
      register: identity_uptime
      changed_when: false
      failed_when: false

    - name: Local users sample
      ansible.builtin.shell: |
        getent passwd | awk -F: '{print $1 ":" $3 ":" $7}' | head -n 30
      register: local_users
      changed_when: false
      failed_when: false

    - name: Running services sample
      ansible.builtin.shell: |
        systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null | head -n 25
      register: running_services_text
      changed_when: false
      failed_when: false

    - name: Listening ports sample
      ansible.builtin.shell: |
        ss -tlnp 2>/dev/null | head -n 30 || netstat -tlnp 2>/dev/null | head -n 30
      register: listening_ports
      changed_when: false
      failed_when: false

    - name: Security logs sample
      ansible.builtin.shell: |
        if [ -f /var/log/auth.log ]; then
          tail -n 20 /var/log/auth.log
        elif [ -f /var/log/secure ]; then
          tail -n 20 /var/log/secure
        else
          journalctl -n 20 -p warning --no-pager 2>/dev/null || echo "Security log unavailable"
        fi
      register: security_logs
      changed_when: false
      failed_when: false

    - name: Inventory summary
      ansible.builtin.debug:
        msg:
          hostname: "{{ ansible_hostname }}"
          os: "{{ ansible_distribution }} {{ ansible_distribution_version }}"
          kernel: "{{ ansible_kernel }}"
          ipv4: "{{ ansible_all_ipv4_addresses }}"
          identity_uptime: "{{ identity_uptime.stdout_lines | default([]) }}"
          local_users: "{{ local_users.stdout_lines | default([]) }}"
          running_services_text: "{{ running_services_text.stdout_lines | default([]) }}"
          listening_ports: "{{ listening_ports.stdout_lines | default([]) }}"
          security_logs: "{{ security_logs.stdout_lines | default([]) }}"
""",
    },
    {
        "id": "linux-compliance",
        "name": "Linux compliance baseline",
        "description": "Detailed SSH, auth, firewall, logging, and hardening checks for Linux hosts",
        "category": "compliance",
        "content": _load_playbook_content("linux_compliance.yml"),
        "content_fast": _load_playbook_content("linux_compliance_fast.yml"),
    },
    {
        "id": "windows-inventory",
        "name": "Windows inventory",
        "description": "Collect Windows system info, services, and disk layout via WinRM",
        "category": "inventory",
        "content": """---
- name: Windows host inventory
  hosts: all
  gather_facts: true
  tasks:
    - name: WinRM connectivity check
      ansible.windows.win_ping:

    - name: System information
      ansible.windows.win_shell: |
        Get-ComputerInfo |
          Select-Object WindowsProductName, WindowsVersion, OsArchitecture, CsName, CsTotalPhysicalMemory |
          Format-List
      register: computer_info
      changed_when: false

    - name: Running services
      ansible.windows.win_shell: |
        Get-Service | Where-Object { $_.Status -eq 'Running' } |
          Select-Object -First 40 Name, DisplayName, Status |
          Format-Table -AutoSize
      register: running_services
      changed_when: false

    - name: Local users
      ansible.windows.win_shell: |
        Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize
      register: local_users
      changed_when: false
      failed_when: false

    - name: Local administrators group members
      ansible.windows.win_shell: |
        Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize
      register: local_admins
      changed_when: false
      failed_when: false

    - name: Disk layout
      ansible.windows.win_shell: |
        Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining |
          Format-Table -AutoSize
      register: disk_layout
      changed_when: false

    - name: Last installed updates
      ansible.windows.win_shell: |
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, InstalledOn, Description | Format-Table -AutoSize
      register: hotfixes
      changed_when: false
      failed_when: false

    - name: Security event logs sample
      ansible.windows.win_shell: |
        Get-WinEvent -LogName Security -MaxEvents 25 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Format-List
      register: security_events
      changed_when: false
      failed_when: false

    - name: Inventory summary
      ansible.builtin.debug:
        msg:
          hostname: "{{ ansible_hostname }}"
          os: "{{ ansible_os_name | default('Windows') }}"
          computer_info: "{{ computer_info.stdout_lines }}"
          running_services: "{{ running_services.stdout_lines }}"
          local_users: "{{ local_users.stdout_lines | default([]) }}"
          local_admins: "{{ local_admins.stdout_lines | default([]) }}"
          disk_layout: "{{ disk_layout.stdout_lines }}"
          hotfixes: "{{ hotfixes.stdout_lines | default([]) }}"
          security_events: "{{ security_events.stdout_lines | default([]) }}"
""",
        "content_fast": """---
- name: Windows host inventory (fast)
  hosts: all
  gather_facts: true
  tasks:
    - name: WinRM connectivity check
      ansible.windows.win_ping:

    - name: System information
      ansible.windows.win_shell: |
        Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture, CsName | Format-List
      register: computer_info
      changed_when: false

    - name: Local users sample
      ansible.windows.win_shell: |
        Get-LocalUser | Select-Object -First 25 Name, Enabled, LastLogon | Format-Table -AutoSize
      register: local_users
      changed_when: false
      failed_when: false

    - name: Running services sample
      ansible.windows.win_shell: |
        Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 25 Name, Status | Format-Table -AutoSize
      register: running_services
      changed_when: false
      failed_when: false

    - name: Disk layout
      ansible.windows.win_shell: |
        Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining | Format-Table -AutoSize
      register: disk_layout
      changed_when: false
      failed_when: false

    - name: Security event logs sample
      ansible.windows.win_shell: |
        Get-WinEvent -LogName Security -MaxEvents 12 | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List
      register: security_events
      changed_when: false
      failed_when: false

    - name: Inventory summary
      ansible.builtin.debug:
        msg:
          hostname: "{{ ansible_hostname }}"
          os: "{{ ansible_os_name | default('Windows') }}"
          computer_info: "{{ computer_info.stdout_lines | default([]) }}"
          local_users: "{{ local_users.stdout_lines | default([]) }}"
          running_services: "{{ running_services.stdout_lines | default([]) }}"
          disk_layout: "{{ disk_layout.stdout_lines | default([]) }}"
          security_events: "{{ security_events.stdout_lines | default([]) }}"
""",
    },
    {
        "id": "windows-compliance",
        "name": "Windows compliance baseline",
        "description": "Detailed account, firewall, update, Defender, audit, and security option checks for Windows",
        "category": "compliance",
        "content": _load_playbook_content("windows_compliance.yml"),
        "content_fast": _load_playbook_content("windows_compliance_fast.yml"),
    },
    {
        "id": "network-compliance",
        "name": "Network compliance baseline",
        "description": "Remote baseline checks aligned with Network-Compliance jobs (hostname, AAA, SSH)",
        "category": "compliance",
        "scope": "network",
        "content": """---
- name: Network compliance baseline
  hosts: all
  gather_facts: false
  tasks:
    - name: Hostname configuration
      ansible.builtin.raw: show running-config | include hostname
      register: hostname_line
      changed_when: false
      ignore_errors: true

    - name: AAA configuration
      ansible.builtin.raw: show running-config | include aaa
      register: aaa_config
      changed_when: false
      ignore_errors: true

    - name: SSH hardening
      ansible.builtin.raw: show running-config | include transport input ssh|ip ssh version
      register: ssh_config
      changed_when: false
      ignore_errors: true

    - name: Compliance summary
      ansible.builtin.debug:
        msg:
          target: "{{ inventory_hostname }}"
          hostname_config: "{{ hostname_line.stdout_lines | default([]) }}"
          aaa_config: "{{ aaa_config.stdout_lines | default([]) }}"
          ssh_config: "{{ ssh_config.stdout_lines | default([]) }}"
""",
        "content_fast": """---
- name: Network compliance baseline (fast)
  hosts: all
  gather_facts: false
  tasks:
    - name: Hostname line
      ansible.builtin.raw: show running-config | include hostname
      register: hostname_line
      changed_when: false
      ignore_errors: true

    - name: AAA sample
      ansible.builtin.raw: show running-config | include aaa new-model|aaa authentication
      register: aaa_config
      changed_when: false
      ignore_errors: true

    - name: Compliance summary
      ansible.builtin.debug:
        msg:
          target: "{{ inventory_hostname }}"
          hostname_config: "{{ hostname_line.stdout_lines | default([]) }}"
          aaa_config: "{{ aaa_config.stdout_lines | default([]) }}"
""",
    },
    {
        "id": "network-connectivity-check",
        "name": "Network connectivity check",
        "description": "ICMP ping and CLI reachability test for network devices",
        "category": "inventory",
        "scope": "network",
        "content": """---
- name: Network device connectivity check
  hosts: all
  gather_facts: false
  tasks:
    - name: ICMP ping
      ansible.builtin.command: ping -c 1 -W 2 {{ ansible_host }}
      delegate_to: localhost
      register: icmp_ping
      changed_when: false
      ignore_errors: true

    - name: Verify CLI access
      ansible.builtin.raw: show version
      register: cli_version
      changed_when: false
      ignore_errors: true

    - name: Connectivity summary
      ansible.builtin.debug:
        msg:
          target: "{{ inventory_hostname }}"
          ping_reachable: "{{ icmp_ping.rc | default(1) == 0 }}"
          cli_reachable: "{{ cli_version.rc | default(1) == 0 }}"
          ping_response: "{{ icmp_ping.stdout_lines | default([]) }}"
          cli_response: "{{ cli_version.stdout_lines | default([]) }}"
""",
    },
    {
        "id": "connectivity-check",
        "name": "Connectivity check",
        "description": "Simple Ansible ping against selected hosts",
        "category": "utility",
        "content": CONNECTIVITY_CHECK_CONTENT,
    },
]


def list_playbook_templates() -> list[dict[str, str]]:
    return list(PLAYBOOK_TEMPLATES)


def get_playbook_template(template_id: str) -> dict[str, str] | None:
    for item in PLAYBOOK_TEMPLATES:
        if item["id"] == template_id:
            return item
    return None
