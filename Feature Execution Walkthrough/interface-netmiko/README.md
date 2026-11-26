# Interface Compliance & Automated Remediation

## Overview

In enterprise network architectures, interface administrative and operational states cannot be left to assumption. Unused switchports left enabled introduce severe Layer 2 security vulnerabilities (e.g., rogue device attachment, spanning-tree loops), while accidentally disabled core uplinks cause immediate, costly network outages. 

The **Interface Compliance & Automated Remediation** module is a production-grade, closed-loop automation engine designed to eliminate this risk. It enforces strict, declarative interface policies by reconciling live Cisco switch state (L1/L2 status) against a **NetBox Source of Truth (SoT)**. 

Rather than relying on brittle screen-scraping or manual CLI audits, this pipeline provides end-to-end lifecycle management: it extracts structured operational data via Cisco pyATS/Genie, identifies exact operational mismatches or unsupported "phantom" hardware declarations, safely remediates drift using idempotent Jinja2 templates (`shutdown` / `no shutdown`), and verifies the fix before logging the outcome to a centralized SIEM.

### Core Engineering Objectives
- **Declarative Baseline:** Establish NetBox as the single source of truth for interface operational intent (`should_be_up`), descriptions, and Layer 2 edge security (STP PortFast, BPDU Guard).
- **Resilient Data Extraction:** Utilize Netmiko and Cisco pyATS/Genie to parse live switch state (`show ip interface brief`) with isolated, fault-tolerant error handling.
- **Compound Health Validation:** Compute a deterministic `is_up` boolean (`status == "up" and protocol == "up"`) to ensure both physical link and data-link layers are fully operational.
- **Safe, Idempotent Remediation:** Apply configuration changes using a targeted Jinja2 template, gated by a global `DRY_RUN` safety switch for Change Advisory Board (CAB) review.
- **Closed-Loop Verification:** Re-poll the device post-remediation to guarantee the physical data plane matches the intended state before marking the task complete.
- **Enterprise Observability:** Stream structured, severity-coded JSON telemetry to Splunk for real-time NOC/SecOps dashboards and immutable audit trails.
- **CI/CD Readiness:** Validate the entire state machine with 13 offline Pytest cases, ensuring zero-regression deployments without requiring live hardware.

---

## Architecture

| Component | Responsibility |
|---|---|
| **NetBox Inventory** | Supplies expected interface states, descriptions, and STP security policies. |
| **Genie Collector** | Collects and parses actual L1/L2 interface operational states over Netmiko SSH. |
| **Interface Builder** | Normalizes collected interface data, enforces lowercase naming, and computes compound `is_up` health. |
| **Compliance Checker** | Compares expected NetBox intent against actual live state, flagging mismatches or phantom hardware. |
| **Remediation Engine** | Applies targeted `shutdown` / `no shutdown` configuration changes via Jinja2. |
| **Post-Validation** | Re-queries and re-evaluates the device to verify that remediation achieved the expected configuration. |

## Topology 

![NetBox Trunk Interfaces CORE-SW-1](screenshots/pnet-lab-topology.png)

### Table of Contents

- [1. Intended State: NetBox Source of Truth (Interface Baseline & Custom Fields)](#1-intended-state-netbox-source-of-truth-interface-baseline--custom-fields)
- [2. Live Device State Collection & Interface Parsing](#2-live-device-state-collection--interface-parsing)
- [3. Interface Compliance Diff Engine & Drift Detection](#3-interface-compliance-diff-engine--drift-detection)
- [4. Automated Interface Remediation & Safe Deployment](#4-automated-interface-remediation--safe-deployment)
- [5. Closed-Loop Post-Remediation Validation & Physical Device Proof](#5-closed-loop-post-remediation-validation--physical-device-proof)
- [6. Splunk Observability & Structured Audit Trail (Interface Baseline)](#6-splunk-observability--structured-audit-trail-interface-baseline)
- [7. Automated Unit Testing & CI/CD Validation (Interface Baseline)](#7-automated-unit-testing--cicd-validation-interface-baseline)
- [Conclusion & Engineering Takeaways](#conclusion--engineering-takeaways)

## 1. Intended State: NetBox Source of Truth (Interface Baseline & Custom Fields)

In an automated infrastructure, interface administrative and operational states must not be left to assumption. Unused switchports left enabled introduce severe security vulnerabilities, while accidentally disabled uplinks cause network outages.

Standard DCIM data models record basic attributes (such as name and description), but enterprise network assurance requires knowing **intended operational intent**:
* *Should this interface actively carry traffic, or should it be administratively shut down?*
* *What Spanning Tree Protocol (STP) edge security policies must be enforced on this port?*

To model these requirements declaratively, the automation engine extends **NetBox DCIM** using **Custom Fields** (`DCIM > Interface`), establishing NetBox as the authoritative Source of Truth (SoT) for interface operational baselines and Layer 2 edge security.

---

### 1. Extending NetBox Schema: `should_be_up` Custom Field

Standard DCIM models only provide an administrative `enabled` flag, which does not define whether an interface is actively expected to pass traffic. A custom Boolean field was provisioned in NetBox to declare operational status:

* **Object Type:** `DCIM > Interface`
* **Internal Name:** `should_be_up`
* **Data Type:** `Boolean` (`True` / `False`)

![NetBox Custom Field Definition](screenshots/netbox-creating-custom-field.png)

![NetBox Interface Add Custom Field](screenshots/netbox-should-be-up-config.png)

* **`should_be_up: True`**: Designates authorized active links (e.g., core uplinks, distribution cross-connects). The engine verifies that line protocol and administrative states are both UP.
* **`should_be_up: False`**: Designates unused, unallocated, or spare ports. The engine enforces that the port is administratively shutdown (`shutdown`).

---

### 2. Interface Baseline Specification: `CORE-SW-1`

On distribution switch `CORE-SW-1`, only authorized distribution downlinks are expected to be active. All unassigned physical interfaces are flagged to be administratively down (`should_be_up = False`):

| Interface | 802.1Q Mode | Administrative (`enabled`) | Operational Intent (`should_be_up`) | Interface Type | Policy Role |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **Ethernet0/0** | `Tagged` | `True` | **`True` (Active)** | 100BASE-TX | Distribution Uplink |
| **Ethernet0/1** | `Access` | `True` | **`False` (Shutdown)** | 1000BASE-T | Unused Access Port |
| **Ethernet0/2** | `—` | `True` | **`False` (Shutdown)** | 1000BASE-T | Unassigned Port |
| **Ethernet0/3** | `Tagged` | `True` | **`True` (Active)** | 1000BASE-T | Core Cross-Connect |
| **Ethernet1/0** | `—` | `True` | **`False` (Shutdown)** | 1000BASE-T | Spare / Unallocated |
| **Ethernet1/1** | `—` | `True` | **`False` (Shutdown)** | 1000BASE-T | Spare / Unallocated |
| **Ethernet1/2** | `—` | `True` | **`False` (Shutdown)** | 1000BASE-T | Spare / Unallocated |
| **Ethernet1/3** | `—` | `True` | **`False` (Shutdown)** | 1000BASE-T | Spare / Unallocated |
| *Vlan1* | *—* | `True` | *—* | *Virtual* | *(Filtered out: SVI)* |

![NetBox Core Switch Interface Baseline](screenshots/netbox-interface-overview.png)

---

### 3. Inventory Ingestion & Context Generation (`src/sot/inventory.py`)

When loading inventory from NetBox, the engine extracts interface parameters while gracefully filtering out non-physical endpoints (`virtual`, `lag`, `bridge`).

It extracts the interface name, description, the `should_be_up` Boolean flag, and associated Spanning-Tree Protocol (STP) security attributes (`portfast`, `bpdu_guard`, etc.):

![Python Inventory Interface Code](screenshots/code-inventory.png)

```python
# src/sot/inventory.py (Interface Ingestion Logic)

# Filter out non-physical and virtual interfaces
if device_interface.type and device_interface.type.value not in [
    "virtual",
    "lag",
    "bridge",
]:
    config_data[host_ip]["interfaces"].append(
        {
            "device_ip": host_ip,
            "interface": device_interface.name,
            "description": device_interface.description or "",
            "should_be_up": device_interface.custom_fields.get(
                "should_be_up", ""
            ),
            "stp": {
                "portfast": device_interface.custom_fields.get(
                    "stp_portfast", False
                ),
                "bpdu_guard": device_interface.custom_fields.get(
                    "stp_bpdu_guard", False
                ),
                "root_guard": device_interface.custom_fields.get(
                    "stp_root_guard", False
                ),
                "loop_guard": device_interface.custom_fields.get(
                    "stp_loop_guard", False
                ),
                "bpdu_filter": device_interface.custom_fields.get(
                    "stp_bpdu_filter", False
                ),
            },
        }
    )
```

---

### 4. Normalized Desired-State Output

During pipeline execution, the inventory builder serializes the NetBox policy into a clean list of interface contracts for `CORE-SW-1`:

![Interface Inventory Runtime Output Part 1](screenshots/print-inventory.png)

![Interface Inventory Runtime Output Part 2](screenshots/print-inventory-2.png)

```json
[
  {
    "device_ip": "10.10.10.10",
    "interface": "Ethernet0/0",
    "description": "Configured via Netmiko",
    "should_be_up": true,
    "stp": {
      "portfast": false,
      "bpdu_guard": false,
      "root_guard": false,
      "loop_guard": false,
      "bpdu_filter": false
    }
  },
  {
    "device_ip": "10.10.10.10",
    "interface": "Ethernet0/1",
    "description": "Configured via Netmiko",
    "should_be_up": false,
    "stp": {
      "portfast": false,
      "bpdu_guard": false,
      "root_guard": false,
      "loop_guard": false,
      "bpdu_filter": false
    }
  },
  {
    "device_ip": "10.10.10.10",
    "interface": "Ethernet0/2",
    "description": "Configured via Netmiko",
    "should_be_up": false,
    "stp": {
      "portfast": false,
      "bpdu_guard": false,
      "root_guard": false,
      "loop_guard": false,
      "bpdu_filter": false
    }
  },
  {
    "device_ip": "10.10.10.10",
    "interface": "Ethernet0/3",
    "description": "Configured via Netmiko",
    "should_be_up": true,
    "stp": {
      "portfast": false,
      "bpdu_guard": false,
      "root_guard": false,
      "loop_guard": false,
      "bpdu_filter": false
    }
  },
  {
    "device_ip": "10.10.10.10",
    "interface": "Ethernet1/0",
    "description": "Configured via Netmiko",
    "should_be_up": false,
    "stp": {
      "portfast": false,
      "bpdu_guard": false,
      "root_guard": false,
      "loop_guard": false,
      "bpdu_filter": false
    }
  }
]
```
Here is the cleaned-up, production-grade version. I have untangled the interleaved drafts, fixed the broken ASCII diagrams, and ensured the code blocks match your screenshots exactly (removing the invented type hints that weren't in your file).

***

## 2. Live Device State Collection & Interface Parsing

To evaluate physical interface states against the declarative NetBox baseline without brittle text scraping, the engine separates data acquisition from schema normalization in a decoupled two-stage pipeline:

![Interface Inventory Runtime Output Part 1](screenshots/build-interface-draw-io.png)

---

### Stage 1: Resilient Multi-Command Collection (`src/collectors/cli/collector.py`)

The `collect_device_state()` routine queries the switch over Netmiko. By specifying `use_genie=True` on `show ip interface brief`, raw CLI terminal tables are parsed directly into structured Python dictionaries.

Each command is encapsulated in its own `try/except` boundary. If an optional feature fails or is unsupported on a specific hardware platform, it defaults safely to an empty dictionary or string, ensuring that interface audits proceed without interruption:

![Collector CLI Implementation](screenshots/collector.png)

```python
# src/collectors/cli/collector.py

def collect_device_state(conn):
    device_state = {}

    # ... VLAN and Switchport Collection ...

    # 3. Layer 3 & Layer 2 Physical Interface Status Collection
    try:
        device_state["interfaces"] = conn.send_command(
            "show ip interface brief", use_genie=True
        )
    except Exception:
        device_state["interfaces"] = {}

    # ... STP, Running-Config, Syslog, and CDP Collection ...

    return device_state
```

#### Collector Design Highlights:
* **`use_genie=True` Integration:** By integrating Cisco pyATS/Genie directly into Netmiko's `send_command`, raw multi-column CLI tables are converted into structured Python dictionaries without brittle regex scraping.
* **Fault-Tolerant Isolation:** If interface collection fails or times out, the collector safely defaults to an empty dictionary (`{}`), ensuring adjacent auditing modules (such as VLANs and trunks) continue processing.

---

### Stage 2: Normalization & Compound Health Logic (`src/collectors/cli/builders.py`)

A network port is not truly functional unless both **Layer 1 (Physical Link)** and **Layer 2 (Data Link / Line Protocol)** are active. 

The `build_interface()` function plucks `device_state["interfaces"]`, standardizes interface identifiers to lowercase, and evaluates whether both states are operational using a compound health assertion:

`is_up = (status == "up") and (protocol == "up")`

![Build Interface Code](screenshots/code-build-interface.png)

```python
# src/collectors/cli/builders.py

# INTERFACE
def build_interface(device_state):
    if not device_state:
        return {}

    device_state_interface = device_state.get("interfaces") or {}
    actual_interfaces = {}
    interfaces = device_state_interface.get("interface", {})

    for interface_name, interface_values in interfaces.items():
        # Defensive check: ensure interface entry is a dictionary
        if not isinstance(interface_values, dict):
            continue

        status = interface_values.get("status", "")
        protocol = interface_values.get("protocol", "")
        interface_name = interface_name.lower().strip()

        actual_interfaces[interface_name] = {
            "interface": interface_name,
            "status": status,
            "protocol": protocol,
            # Compound health assertion: Both L1 and L2 must be 'up'
            "is_up": status == "up" and protocol == "up",
        }

    return actual_interfaces
```

---

### 3. Normalized Live State Output

Below is the verified dictionary returned by `build_interface()` after parsing `CORE-SW-1`:

![Build Interface Runtime Output](screenshots/print-build-interface.png)

```json
{
  "ethernet0/0": {
    "interface": "ethernet0/0",
    "status": "up",
    "protocol": "up",
    "is_up": true
  },
  "ethernet0/1": {
    "interface": "ethernet0/1",
    "status": "up",
    "protocol": "up",
    "is_up": true
  },
  "ethernet0/2": {
    "interface": "ethernet0/2",
    "status": "up",
    "protocol": "up",
    "is_up": true
  },
  "ethernet0/3": {
    "interface": "ethernet0/3",
    "status": "up",
    "protocol": "up",
    "is_up": true
  },
  "ethernet1/0": {
    "interface": "ethernet1/0",
    "status": "up",
    "protocol": "up",
    "is_up": true
  },
  "ethernet1/1": {
    "interface": "ethernet1/1",
    "status": "up",
    "protocol": "up",
    "is_up": true
  }
}
```

---

### 4. Operational Drift Baseline

Comparing this live operational output against the **NetBox Desired State** reveals immediate configuration drift:

* **NetBox Policy:** Interfaces `Ethernet0/1`, `Ethernet0/2`, `Ethernet1/0`, and `Ethernet1/1` are unallocated spare ports explicitly flagged with **`should_be_up: False`** (intended to be administratively disabled).
* **Live Switch State:** Every single physical interface on the switch is currently **`is_up: true`** (`status: "up"`, `protocol: "up"`).

> **Next Step:** This normalized operational dictionary is passed directly into `check_interface()`, which evaluates each port's live state against NetBox intent and flags active spare ports as policy violations.

## 3. Interface Compliance Diff Engine & Drift Detection

The interface compliance module reconciles the operational health and existence of physical switchports against declarative NetBox policies. Operating as a closed‑loop state machine, it verifies that active links are operational, enforces administrative shutdown on unassigned ports, detects unsupported (phantom) hardware declarations, and executes post‑validation verification.

![Interface Check Code](screenshots/compliance-draw-io.png)

---

### 1. Two‑Gate Diff Engine (`src/compliance/switching/interface/check.py`)

The `check_interface()` function validates every interface against two deterministic failure gates:

1. **Hardware Support / Existence Gate:** Verifies that the interface declared in NetBox actually exists on physical hardware (`actual = actual_config.get(exp_interface)`). If absent, the check halts immediately and flags hardware incompatibility.
2. **Compound Operational Status Gate:** Compares the intended operational state (`exp_is_up`, from NetBox `should_be_up`) against the live compound state (`actual_is_up = status == "up" and protocol == "up"`). If NetBox declares `should_be_up: False`, the switchport cannot be running with both link status and line protocol `up`.

![Interface Check Code](screenshots/code-check-interface.png)

```python
# src/compliance/switching/interface/check.py

def check_interface(expected_int, actual_config):
    failures = []
    exp_interface = expected_int.get("interface", "").lower().strip()
    exp_is_up = expected_int.get("should_be_up", False)

    actual = actual_config.get(exp_interface)
    if not actual:
        failures.append(
            f"[Interface] Device does not support this interface | Interface: {exp_interface}"
        )
        return False, failures
    actual_is_up = actual.get("is_up", False)
    if exp_is_up != actual_is_up:
        failures.append(
            f"Mismatched Interface Operational Status / Protocol State | Interface: {exp_interface} | "
            f"Expected Should Be Up/Up: {exp_is_up} | "
            f"Actual Should be Up/Up: {actual_is_up}"
        )

    return len(failures) == 0, failures
```

---

### 2. Closed‑Loop Compliance Orchestrator (`src/compliance/switching/interface/compliance.py`)

The compliance manager (`compliance_interface()`) iterates through expected interfaces, bypasses healthy links, records drift, dispatches remediation, and triggers closed‑loop post‑validation:

![Interface Compliance Implementation Part 1](screenshots/code-compliance-1.png)

![Interface Compliance Implementation Part 2](screenshots/code-compliance-2.png)

```python
# src/compliance/switching/interface/compliance.py

def compliance_interface(sesh, device_ip, context, device_state, device_result, log, transport):
    exp_interfaces = context.get("interfaces", [])
    act_interfaces = build_interface(device_state)
    interfaces_updated = False

    for int_data in exp_interfaces:
        interface = int_data.get("interface", "")
        description = int_data.get("description", "")
        should_be_up = int_data.get("should_be_up", False)

        # 1. Evaluate interface against multi-tier check
        ok, failures = check_interface(int_data, act_interfaces)

        # 2. Compliant Path: Log pass and bypass changes
        if ok:
            log.info(
                "interface_compliant",
                extra={
                    "device_ip": device_ip,
                    "event_type": "interface_compliance",
                    "component": "main_process",
                    "protocol": "interface",
                    "transport": transport,
                    "interface": interface,
                    "description": description,
                    "should_be_up": should_be_up,
                    "compliant": ok,
                    "failure_count": 0,
                    "failures": failures,
                    "status": StepStatus.SUCCESS.value,
                    "detail": "Interface Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"Interface Configuration Already Compliant | Interface: {interface} | "
                f"Description: {description} | Should Be Up: {should_be_up}"
            )
            continue

        # 3. Drift Path: Record initial issues and issue warning
        device_result["initial_issues"].extend(failures)
        log.warning(
            "interface_drift",
            extra={
                "device_ip": device_ip,
                "event_type": "interface_compliance",
                "component": "main_process",
                "protocol": "interface",
                "transport": transport,
                "interface": interface,
                "should_be_up": should_be_up,
                "compliant": ok,
                "failure_count": len(failures),
                "failures": failures,
                "status": StepStatus.FAILED.value,
                "detail": "Interface Configuration Non-Compliant",
            },
        )

        # 4. Dispatch remediation
        result = configure_interface(sesh, int_data, log)
        if result.get("status") == OperationalStatus.SUCCESS.value:
            interfaces_updated = True
            device_result["actions_taken"].append(result.get("summary"))
        else:
            device_result["critical_issues"].append(
                f"Failed To Remediate Interface Configuration | "
                f"Interface: {interface} | Description: {description} | "
                f"Should Be Up: {should_be_up}"
            )

    # 5. Closed-Loop Post-Validation Pass (Skipped if DRY_RUN)
    if interfaces_updated and not DRY_RUN:
        new_state = collect_device_state(sesh)
        new_interface = build_interface(new_state)

        for int_data in exp_interfaces:
            ok, failures = check_interface(int_data, new_interface)
            if not ok:
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
                log.error("interface_post_validation_failed", extra={...})
            else:
                log.info("interface_post_validation_success", extra={...})
```

---

### 3. Runtime Drift Scenarios & Evidence

The compliance engine was validated on `CORE-SW-1` against two operational drift conditions:

#### Scenario A - Operational Status Drift (Unassigned Ports Left Active)
On `CORE-SW-1`, core uplinks `Ethernet0/0` and `Ethernet0/3` were verified compliant (empty failure list `[]`). However, unassigned spare ports (`Ethernet0/1`, `Ethernet0/2`, `Ethernet1/0`–`1/3`) were left enabled on the switch, violating the NetBox policy (`should_be_up: False`):

![Interface Operational Drift Terminal Output](screenshots/check-interface-mismatched-operational-state.png)

```text
2026-11-23 02:22:14,929 - INFO - interface_compliant
2026-11-23 02:22:14,929 - WARNING - interface_drift
2026-11-23 02:22:14,929 - WARNING - interface_drift
2026-11-23 02:22:14,930 - INFO - interface_compliant
2026-11-23 02:22:14,930 - WARNING - interface_drift
2026-11-23 02:22:14,930 - WARNING - interface_drift
2026-11-23 02:22:14,930 - WARNING - interface_drift
2026-11-23 02:22:14,930 - WARNING - interface_drift
2026-11-23 02:22:14,930 - INFO - trunk_interface_compliant
2026-11-23 02:22:14,934 - INFO - trunk_interface_compliant
[]
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet0/1 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet0/2 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
[]
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/0 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/1 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/2 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/3 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
2026-11-23 02:22:14,957 - WARNING - stp_interfaces_non_compliant
```

The two bare `[]` lines are the compliant uplinks (`Ethernet0/0`, `Ethernet0/3`); the six `Mismatched` strings are the spare ports whose live `is_up: True` contradicts NetBox intent `should_be_up: False`.

---

#### Scenario B - Phantom / Unsupported Hardware Interface Detection
I provisioned an unauthorized interface (`GigabitEthernet1/0`) in NetBox under `CORE-SW-1` (testing purposes):

![NetBox Phantom Interface Added](screenshots/check-interface-intentionally-adding-missing-interface.png)

![NetBox Edit Phantom Interface](screenshots/check-interface-intentionally-adding-missing-interface-overview.png)

Because physical switch `CORE-SW-1` only possesses `Ethernet` modular ports, **Gate 1** immediately caught that the hardware does not support the declared interface (note the green `should_be_up` check in the table is irrelevant, Gate 1 short‑circuits before the status comparison):

![Phantom Interface Terminal Output](screenshots/check-interface-device-does-not-support-interface.png)

```text
2026-11-23 02:31:06,397 - INFO - interface_compliant
2026-11-23 02:31:06,398 - WARNING - interface_drift
2026-11-23 02:31:06,398 - WARNING - interface_drift
2026-11-23 02:31:06,398 - INFO - interface_compliant
2026-11-23 02:31:06,399 - WARNING - interface_drift
2026-11-23 02:31:06,399 - WARNING - interface_drift
2026-11-23 02:31:06,399 - WARNING - interface_drift
2026-11-23 02:31:06,400 - WARNING - interface_drift
2026-11-23 02:31:06,400 - INFO - trunk_interface_compliant
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet0/1 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet0/2 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/0 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/1 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/2 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/3 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True']
['[Interface] Device does not support this interface | Interface: gigabitethernet1/0']
2026-11-23 02:31:06,405 - INFO - trunk_interface_compliant
2026-11-23 02:31:06,430 - WARNING - stp_interfaces_non_compliant
```

---

### 4. Compliance Evaluation Matrix

| Live Device State | NetBox Declared Intent | `check_interface()` Result | Engine Action |
| :--- | :--- | :---: | :--- |
| `status: up`<br>`protocol: up` | `should_be_up: True` | **PASS (Compliant)** | Log `interface_compliant`; bypass changes. |
| `status: up`<br>`protocol: up` | `should_be_up: False` | **FAIL (Status Mismatch)** | Log `interface_drift`; queue `shutdown` remediation. |
| `status: administratively down` | `should_be_up: True` | **FAIL (Link Down)** | Log `interface_drift`; queue `no shutdown` remediation. |
| Port not found in `show ip int brief` | Declared in NetBox | **FAIL (Unsupported Interface)** | Flag fatal drift: `Device does not support this interface`; prevent command execution. |

## 4. Automated Interface Remediation & Safe Deployment

When the compliance engine detects an operational discrepancy (such as an unassigned port left active or a missing description), it dispatches targeted remediation to `configure_interface()` in `src/remediation/switching/interface.py`.

The remediation architecture enforces deterministic state using a **declarative Jinja2 template** (`templates/interface.j2`) and protects production networks with a built‑in **Dry‑Run safety gate**.

![Interface Jinja2 Template](screenshots/remediation-draw-io.png)

---

### 1. Declarative Interface Template (`templates/interface.j2`)

The Jinja2 template evaluates the NetBox `should_be_up` Boolean flag to dynamically generate the appropriate administrative state (`shutdown` vs `no shutdown`) and binds the engineering description:

![Interface Jinja2 Template](screenshots/jinja-2-template.png)

```jinja2
{# templates/interface.j2 #}
{% for i in interface_data %}
interface {{ i.interface }}
{% if i.should_be_up %}
no shutdown
description {{ i.description }}
{% else %}
shutdown
description {{ i.description }}
{% endif %}
{% endfor %}
```

---

### 2. Remediation Handler Implementation (`src/remediation/switching/interface.py`)

The `configure_interface()` routine translates NetBox intent into atomic CLI command sets, enforces pre‑flight dry‑run evaluation, pushes configurations over Netmiko, and logs audit events:

![Remediation Interface Code](screenshots/code-configure-interface.png)

```python
# src/remediation/switching/interface.py

def configure_interface(conn, interface_data, device_ip, transport, log):
    interface = interface_data.get("interface", "")
    description = interface_data.get("description", "")
    should_be_up = interface_data.get("should_be_up", False)
    if should_be_up:
        state = "no shutdown"
    else:
        state = "shutdown"
    try:
        template = template_env.get_template("interface.j2")
        commands = template.render(
            interface=interface,
            description=description,
            state=state
        ).splitlines()
        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (f"[DRY_RUN] Would Change Interface Status | Interface: {interface} "
                            f"| Should Be Up/Up: {should_be_up}"
                )
            }

        conn.send_config_set(commands)

        log.info(
            "interface_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "interface_automation",
                "event_type": "interface_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "should_be_up": should_be_up,
                "detail": (f"Interface Status Successfully changed | Interface: {interface} "
                           f"| Should Be Up/Up: {should_be_up}"
                )
            }
        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (f"Interface Status Successfully Changed | Interface: {interface} "
                        f"| Should Be Up/Up: {should_be_up}"
            )
        }
    except Exception as e:
        log.error("interface_config_failed", extra={"device_ip": conn.device_ip, "error": str(e)})
        return {
            "status": OperationalStatus.FAILED_CONFIG.value,
            "summary": f"Failed to configure interface {interface}: {str(e)}"
        }
```

---

### 3. Dry‑Run Audit Reporting (`final_compliance_report.json`)

![Final Compliance Report Dry Run Interfaces](screenshots/dry-run-draw-io.png)

When running in dry‑run mode (`DRY_RUN = True`), all proposed remediations are cataloged in `final_compliance_report.json` without modifying hardware. The report documents verified compliant uplinks alongside planned shutdown actions for spare ports:

![Final Compliance Report Dry Run Interfaces](screenshots/dry-run-final-report-json.png)



```json
{
  "device_name": "CORE-SW-1",
  "device_ip": "10.10.10.10",
  "status": "COMPLIANT",
  "actions_taken": [
    "Interface Configuration Already Compliant | Interface: Ethernet0/0 | Description: Configured via Netmiko | Should Be Up: True",
    "Interface Configuration Already Compliant | Interface: Ethernet0/3 | Description: Configured via Netmiko | Should Be Up: True",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet0/1 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet0/2 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet1/0 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet1/1 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet1/2 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: Ethernet1/3 | Description: Configured via Netmiko | Should Be Up: False",
    "[DRY_RUN] Would Configure Interface | Interface: GigabitEthernet1/0 | Description: | Should Be Up: True"
  ]
}
```

---

## 5. Closed‑Loop Post‑Remediation Validation & Physical Device Proof

Issuing a `shutdown` or `no shutdown` command over SSH does not prove that an interface transitioned into the intended state (e.g., transceivers can hang, SFP errors can persist, or physical faults can prevent link negotiation). The engine enforces a **closed‑loop verification pass**:

1. It re‑collects live device operational state (`collect_device_state(sesh)`).
2. It re‑normalizes interface data through `build_interface(new_state)`.
3. It re‑runs `check_interface()` to assert that the operational state now matches NetBox intent.

![Final Compliance Report Dry Run Interfaces](screenshots/closed-loop-diagram-draw-io.png)

After live remediation commands are pushed, the engine re‑polls the switch's operational state via Genie (`show ip interface brief`) to verify that all target interfaces transitioned to the intended state on physical hardware.

---

### 5.1 Device State: BEFORE Remediation (`CORE-SW-1`)

Before running remediation, all physical interfaces were operating in an unmanaged active state (`is_up: true`), despite NetBox policy declaring that unassigned ports (`Ethernet0/1`, `Ethernet0/2`, `Ethernet1/0`–`1/3`) should be down:

![Show IP Interface Brief Before Remediation](screenshots/show-ip-int-brief-before.png)

```text
CORE-SW-1#sh ip int brief
Interface                  IP-Address      OK? Method Status                Protocol
Ethernet0/0                unassigned      YES unset  up                    up
Ethernet0/1                unassigned      YES unset  up                    up
Ethernet0/2                unassigned      YES unset  up                    up
Ethernet0/3                unassigned      YES unset  up                    up
Ethernet1/0                unassigned      YES unset  up                    up
Ethernet1/1                unassigned      YES unset  up                    up
Ethernet1/2                unassigned      YES unset  up                    up
Ethernet1/3                unassigned      YES unset  up                    up
Vlan1                      10.10.10.10     YES NVRAM  up                    up
```

> **Observed drift:** the six spare ports (`Ethernet0/1`, `0/2`, `1/0`–`1/3`) are `up/up` while NetBox mandates `should_be_up: False`. The two core trunks (`0/0`, `0/3`) are correctly `up/up`.

---

### 5.2 Execution Audit: Cisco Console Syslog (`vty0`)

When remediation executed, `CORE-SW-1` logged incoming configuration changes pushed by the automation service account (`sysadmin`) over `vty0`, followed by link‑down state‑change notices:

![Cisco Console Configured by Sysadmin](screenshots/show-ip-int-brief-console-vty-change.png)

```text
*Nov 23 07:49:04.729: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:05.073: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:05.440: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:05.780: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:06.110: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:06.462: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:06.648: %LINK-5-CHANGED: Interface Ethernet0/1, changed state to administratively down
*Nov 23 07:49:06.831: %SYS-5-CONFIG_I: Configured from console by sysadmin on vty0 (172.16.109.1)
*Nov 23 07:49:06.989: %LINK-5-CHANGED: Interface Ethernet0/2, changed state to administratively down
*Nov 23 07:49:07.351: %LINK-5-CHANGED: Interface Ethernet1/0, changed state to administratively down
*Nov 23 07:49:07.648: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet0/1, changed state to down
*Nov 23 07:49:07.708: %LINK-5-CHANGED: Interface Ethernet1/1, changed state to administratively down
*Nov 23 07:49:07.992: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet0/2, changed state to down
*Nov 23 07:49:08.030: %LINK-5-CHANGED: Interface Ethernet1/2, changed state to administratively down
*Nov 23 07:49:08.352: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/0, changed state to down
*Nov 23 07:49:08.374: %LINK-5-CHANGED: Interface Ethernet1/3, changed state to administratively down
*Nov 23 07:49:08.709: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/1, changed state to down
*Nov 23 07:49:09.034: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/2, changed state to down
*Nov 23 07:49:09.382: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/3, changed state to down
```

---

### 5.3 Device State: AFTER Automated Remediation (`CORE-SW-1`)

Following automated execution, the switch state was re‑polled. All unassigned ports were confirmed to be in an `administratively down` state, while critical infrastructure uplinks (`Ethernet0/0` and `Ethernet0/3`) remained fully operational:

![Show IP Interface Brief After Remediation](screenshots/show-ip-interface-brief-after-config.png)

```text
CORE-SW-1#sh ip int brief
Interface                  IP-Address      OK? Method Status                Protocol
Ethernet0/0                unassigned      YES unset  up                    up
Ethernet0/1                unassigned      YES unset  administratively down down
Ethernet0/2                unassigned      YES unset  administratively down down
Ethernet0/3                unassigned      YES unset  up                    up
Ethernet1/0                unassigned      YES unset  administratively down down
Ethernet1/1                unassigned      YES unset  administratively down down
Ethernet1/2                unassigned      YES unset  administratively down down
Ethernet1/3                unassigned      YES unset  administratively down down
Vlan1                      10.10.10.10     YES NVRAM  up                    up
```

![Running Config After Interface Remediation](screenshots/show-ip-int-brief-show-run-after-configuration.png)

```cisco
interface Ethernet0/0
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 1,10,20,30,40,50,60,70,999
 switchport mode trunk
 duplex auto
!
interface Ethernet0/1
 description Configured via Netmiko
 shutdown
 duplex auto
!
interface Ethernet0/2
 description Configured via Netmiko
 shutdown
 duplex auto
!
interface Ethernet0/3
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 1,10,20,30,40,50,60,70,999
 switchport mode trunk
 duplex auto
!
interface Ethernet1/0
 description Configured via Netmiko
 shutdown
 duplex auto
!
interface Ethernet1/1
 description Configured via Netmiko
 shutdown
 duplex auto
!
interface Ethernet1/2
 description Configured via Netmiko
 shutdown
 duplex auto
!
interface Ethernet1/3
 description Configured via Netmiko
 shutdown
```

---

### 5.4 Running Configuration Diff

```diff
 interface Ethernet0/1
+ description Configured via Netmiko
+ shutdown
  duplex auto
 !
 interface Ethernet0/2
+ description Configured via Netmiko
+ shutdown
  duplex auto
 !
 interface Ethernet1/0
+ description Configured via Netmiko
+ shutdown
  duplex auto
 !
 interface Ethernet1/1
+ description Configured via Netmiko
+ shutdown
  duplex auto
 !
 interface Ethernet1/2
+ description Configured via Netmiko
+ shutdown
  duplex auto
 !
 interface Ethernet1/3
+ description Configured via Netmiko
+ shutdown
  duplex auto
```

> **Takeaway:**
> The engine selectively remediates only the drifted interfaces. It shuts down unmanaged ports to eliminate Layer 2 security attack surfaces while ensuring that production core links remain untouched.

## 6. Splunk Observability & Structured Audit Trail (Interface Baseline)

To satisfy enterprise change‑audit requirements, every stage of physical interface lifecycle management baseline auditing, drift detection, remediation dispatch, exception handling, and post‑validation—generates structured JSON events streamed directly to **Splunk via HTTP Event Collector (HEC)** (`index="network_automation"`, `sourcetype="_json"`).

Events map directly to Cisco syslog severity levels (`cisco_sev`), enabling Security Operations (SecOps) and Network Operations Centers (NOC) to monitor interface flapping, detect unauthorized active ports, and audit automated remediation actions in real time.

```spl
index="network_automation" sourcetype="_json" protocol="interface"
| table asctime cisco_sev event_type message interface should_be_up status compliant detail
```

> **Tip:** In the screenshots the lifecycle phases were isolated with keyword filters appended to the base search  `index="network_automation" "Configured"` for the drift/remediation events and `index="network_automation" "Exception"` for the caught template fault which is a fast way to pull a single phase from the index.

---

### Interface Telemetry Lifecycle Matrix

The engine records five discrete operational transitions across managed interfaces on `CORE-SW-1` (`10.10.10.10`):

| Lifecycle Phase | Event Type (`event_type`) | Message (`message`) | Cisco Severity | Status | Operational Significance |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **1. Pre‑Check Pass** | `interface_compliance` | `interface_compliant` | `6 (INFO)` | `SUCCESS` | Interface operational state and description already match NetBox intent; bypassed. |
| **2. Drift Detected** | `interface_compliance` | `interface_drift` | `4 (WARN)` | `FAILED` | Interface state mismatch detected (e.g., spare port active when expected down). |
| **3. Remediation Push** | `interface_config` | `interface_config` | `6 (INFO)` | `SUCCESS` | `shutdown` / `no shutdown` command set pushed via Netmiko. |
| **4. Post‑Validation** | `interface_compliance` | `interface_post_validation_success` | `6 (INFO)` | `SUCCESS` | Re‑queried L1/L2 state confirms the interface matches NetBox intent. |
| **5. Exception Tracking** | `interface_config` | `interface_config` | `6 (INFO)` | `ERROR` | `try/except` boundary caught a Jinja2 template‑syntax fault without crashing. |

---

### Splunk Event Evidence & Payload Breakdown

#### 1. Pre‑Check Pass (`interface_compliant`)

When an interface's live L1/L2 state and description already match NetBox intent on the initial scan, the engine logs an informational pass with zero failures and bypasses remediation entirely. Here the distribution uplink `Ethernet0/3` (`10.10.10.10`) was verified compliant against `should_be_up: True`:

![Splunk Interface Already Compliant](screenshots/splunk-already-compliant.png)

```json
{
  "asctime": "2026-11-23 02:53:07,057",
  "cisco_appname": "SRC",
  "cisco_msgname": "INFO",
  "cisco_sev": 6,
  "compliant": true,
  "component": "main_process",
  "description": "Configured via Netmiko",
  "detail": "Interface Configuration Already Compliant",
  "dev": "10.10.10.10",
  "device_ip": "10.10.10.10",
  "event_type": "interface_compliance",
  "failures": [],
  "failures_count": 0,
  "hostname": "mx",
  "interface": "Ethernet0/3",
  "level": "INFO",
  "message": "interface_compliant",
  "protocol": "interface",
  "seqnum": 48,
  "should_be_up": true,
  "status": "SUCCESS",
  "tags": {},
  "taskName": null,
  "transport": "NETMIKO"
}
```
#### 2. Configuration Drift Alert (`interface_drift`)
Triggered when a live interface state deviates from NetBox intent. On `CORE-SW-1`, spare port `Ethernet1/3` was left administratively **up** while NetBox declared `should_be_up: False`. The engine flags a `WARNING` (Cisco severity 4) with the exact L1/L2 diff:

![Splunk Interface Drift Alert](screenshots/splunk-non-compliant.png)

```json
{
  "asctime": "2026-11-23 02:53:08,365",
  "cisco_appname": "SRC",
  "cisco_msgname": "WARNING",
  "cisco_sev": 4,
  "compliant": false,
  "component": "main_process",
  "description": "Configured via Netmiko",
  "detail": "Interface Configuration Non-Compliant",
  "dev": "10.10.10.10",
  "device_ip": "10.10.10.10",
  "event_type": "interface_compliance",
  "failures": [
    "Mismatched Interface Operational Status / Protocol State | Interface: ethernet1/3 | Expected Should Be Up/Up: False | Actual Should be Up/Up: True"
  ],
  "failures_count": 1,
  "hostname": "mx",
  "interface": "Ethernet1/3",
  "level": "WARNING",
  "message": "interface_drift",
  "protocol": "interface",
  "seqnum": 55,
  "should_be_up": false,
  "status": "FAILED",
  "tags": {},
  "taskName": null,
  "transport": "NETMIKO"
}
```

---

#### 3. Targeted Remediation Execution (`interface_config`)
Emitted immediately after Netmiko pushes the rendered `interface.j2` command set to heal the port. Note the populated `tags` object (`ThreadPoolExecutor-0_1`), proving the remediation ran on a worker thread:

![Splunk Interface Configured Successfully](screenshots/splunk-configured-successfully.png)

```json
{
  "asctime": "2026-11-23 02:57:41,120",
  "cisco_appname": "SRC",
  "cisco_msgname": "INFO",
  "cisco_sev": 6,
  "component": "interface_automation",
  "detail": "Interface Operational State (Status/Protocol) Successfully changed | Interface: Ethernet1/3 | Should Be Up/Up: False",
  "dev": "10.10.10.10",
  "device_ip": "10.10.10.10",
  "event_type": "interface_config",
  "hostname": "mx",
  "interface": "Ethernet1/3",
  "level": "INFO",
  "message": "interface_config",
  "seqnum": 54,
  "should_be_up": false,
  "status": "SUCCESS",
  "tags": {
    "pid": 693193,
    "pname": "MainProcess",
    "tid": 140021386434240,
    "tname": "ThreadPoolExecutor-0_1"
  },
  "taskName": null,
  "transport": "NETMIKO"
}
```

---

#### 4. Closed‑Loop Post‑Validation Success (`interface_post_validation_success`)
After the configuration is pushed, the engine re‑collects live device state via Genie to verify the operational switchport matches NetBox intent. When L1 status and L2 protocol both resolve to the intended state, a post‑validation confirmation is indexed:

![Splunk Interface Post-Validation Success](screenshots/splunk-post-validation-successful.png)

```json
{
  "asctime": "2026-11-23 02:53:19,548",
  "cisco_appname": "SRC",
  "cisco_msgname": "INFO",
  "cisco_sev": 6,
  "compliant": true,
  "component": "main_process",
  "description": "Configured via Netmiko",
  "detail": "Interface Configuration Post Validation Successful",
  "dev": "10.10.10.10",
  "device_ip": "10.10.10.10",
  "event_type": "interface_compliance",
  "failures": [],
  "failures_count": 0,
  "hostname": "mx",
  "interface": "Ethernet1/3",
  "level": "INFO",
  "message": "interface_post_validation_success",
  "protocol": "interface",
  "seqnum": 66,
  "should_be_up": false,
  "status": "SUCCESS",
  "tags": {},
  "taskName": null,
  "transport": "NETMIKO"
}
```

---

#### 5. Exception & Fault Observability (`status: ERROR`)
The remediation engine encapsulates template rendering and command execution inside a `try...except` boundary. In an earlier run (`02:42`), the `interface.j2` template contained an **unclosed `{% for %}` block**, so Jinja2 raised a `TemplateSyntaxError` during `render()`. The engine caught it, indexed the fault as an `ERROR` event with the full parser message, and continued auditing the remaining interfaces without crashing:

![Splunk Interface Exception Logged](screenshots/splunk-try-exception-error-jinja.png)

```json
{
  "asctime": "2026-11-23 02:42:26,331",
  "cisco_appname": "SRC",
  "cisco_msgname": "INFO",
  "cisco_sev": 6,
  "component": "interface_automation",
  "detail": "Try/Exception Error | Interface Status Configuration | Interface: Ethernet1/3 | Should Be Up/Up: False | Error: Unexpected end of template. Jinja was looking for the following tags: 'endfor' or 'else'. The innermost block that needs to be closed is 'for'.",
  "dev": "10.10.10.10",
  "device_ip": "10.10.10.10",
  "event_type": "interface_config",
  "hostname": "mx",
  "interface": "Ethernet1/3",
  "level": "INFO",
  "message": "interface_config",
  "seqnum": 29,
  "should_be_up": false,
  "status": "ERROR",
  "tags": {
    "pid": 641021,
    "pname": "MainProcess",
    "tid": 139636932335296,
    "tname": "ThreadPoolExecutor-0_1"
  },
  "taskName": null,
  "transport": "NETMIKO"
}
```

The fault was subsequently resolved by completing the template's control blocks. The corrected `templates/interface.j2` (note the balanced `{% if %}…{% else %}…{% endif %}` and `{% endfor %}`) is shown below:

![Interface Jinja2 Template (Fixed)](screenshots/splunk-intentional-jinja-mistake.png)

```jinja2
{# templates/interface.j2 #}
{% for i in interface_data %}
interface {{ i.interface }}
{% if i.should_be_up %}
no shutdown
description {{ i.description}}
{% else %}
shutdown
description {{ i.description}}
{% endif %}
{% endfor %}
```

> **Enterprise Reliability Takeaway:**
> By streaming both successful state changes **and unhandled template/transport exceptions** into Splunk, the automation engine gives operations teams real‑time visibility into silent failures — here, a broken Jinja2 block was caught and indexed at `02:42` instead of crashing the audit pipeline, then fixed and re‑validated at `02:53`–`02:57`.

---

### Internal Execution Tracking

Beyond real‑time SIEM streaming, the automation engine maintains state inside the device execution context to generate `final_compliance_report.json` and `network_compliance_report.txt`:

* **`device_result["initial_issues"]`**: Collects all L1/L2 status diffs detected before remediation (used to quantify interface drift rates).
* **`device_result["actions_taken"]`**: Records every `shutdown` / `no shutdown` push or `[DRY_RUN]` preview executed during the run.
* **`device_result["critical_issues"]`**: Populated only if remediation fails over SSH, a template/transport exception is raised, or post‑validation fails after changes were applied.

## 7. Automated Unit Testing & CI/CD Validation (Interface Baseline)

To ensure high‑availability operational assurance without requiring access to physical hardware, the interface baseline module includes a comprehensive **100% offline unit‑testing suite** powered by **Pytest** and **unittest.mock**.

The test suite validates data parsing, case‑normalization, compound link‑health assertions, and closed‑loop compliance states in **1.53 seconds** across 13 test cases (0.68s builder + 0.85s compliance).

![Interface Jinja2 Template (Fixed)](screenshots/pytests-draw-io.png)

---

### Layer 1: Interface Builder & Compound Health Tests (`test_build_interface.py`)

This suite verifies that `build_interface()` accurately normalizes Genie operational data, enforces lowercase formatting, and computes the compound `is_up` Boolean flag across all link permutations.

#### Test Cases Covered:
1. **`test_build_interface_valid`**: Evaluates multi‑port Genie output (`interface_genie_output`). Asserts `gigabitethernet0/0` (`status: "up"`, `protocol: "up"`) computes `is_up: True`, while `gigabitethernet1/3` (`status: "down"`, `protocol: "down"`) computes `is_up: False`.
2. **`test_build_interface_empty`**: Boundary test confirming `build_interface(None)`, `build_interface({})`, `build_interface({"not_interface": {}})`, and `build_interface({"interface": None})` safely return `{}` without uncaught exceptions.
3. **`test_build_interface_is_down`**: Strictly validates the compound Layer 1 / Layer 2 health truth table — `up`/`down` → `False`, `down`/`up` → `False`, `up`/`up` → `True`.
4. **`test_build_interface_lowercase`**: Injects mixed‑casing (`GigabitEthernet0/0`). Confirms dictionary keys are normalized to lowercase (`gigabitethernet0/0`).
5. **`test_build_interface_non_dictionary`**: Validates that non‑dictionary interface values in the Genie output are safely ignored.
6. **`test_build_interface_missing_fields`**: Confirms that interfaces missing explicit `status` or `protocol` attributes default safely to empty strings.

#### Excerpt:

![Interface Builder Unit Tests Passed](screenshots/unit-test-code-build-interface.png)

```python
# tests/unit/collectors/cli/test_build_interface.py (Excerpt)

def test_build_interface_valid(interface_genie_output):
    result = build_interface(interface_genie_output)

    assert "gigabitethernet0/0" in result
    assert result["gigabitethernet0/0"]["status"] == "up"
    assert result["gigabitethernet0/0"]["protocol"] == "up"
    assert result["gigabitethernet0/0"]["is_up"] == True

    assert result["gigabitethernet1/3"]["status"] == "down"
    assert result["gigabitethernet1/3"]["protocol"] == "down"
    assert result["gigabitethernet1/3"]["is_up"] == False

def test_build_interface_is_down():
    data = {
        "interfaces": {
            "interface": {
                "GigabitEthernet0/0": {"status": "up", "protocol": "down"},
                "GigabitEthernet0/1": {"status": "down", "protocol": "up"},
                "GigabitEthernet0/2": {"status": "up", "protocol": "up"}
            }
        }
    }
    result = build_interface(data)
    assert result["gigabitethernet0/0"]["is_up"] is False
    assert result["gigabitethernet0/1"]["is_up"] is False
    assert result["gigabitethernet0/2"]["is_up"] is True
```

#### Terminal Execution:

![Interface Builder Unit Tests Passed](screenshots/unit-test-build-interface-passed.png)

```bash
$ PYTHONPATH=. pytest tests/unit/collectors/cli/test_build_interface.py -v
============================= test session starts ==============================
platform linux -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0 -- /home/rich/Documents/network-automation-engine-main/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/rich/Documents/network-automation-engine-main
collected 6 items

tests/unit/collectors/cli/test_build_interface.py::test_build_interface_valid PASSED          [ 16%]
tests/unit/collectors/cli/test_build_interface.py::test_build_interface_empty PASSED          [ 33%]
tests/unit/collectors/cli/test_build_interface.py::test_build_interface_is_down PASSED        [ 50%]
tests/unit/collectors/cli/test_build_interface.py::test_build_interface_lowercase PASSED      [ 66%]
tests/unit/collectors/cli/test_build_interface.py::test_build_interface_non_dictionary PASSED [ 83%]
tests/unit/collectors/cli/test_build_interface.py::test_build_interface_missing_fields PASSED [100%]

============================== 6 passed in 0.68s ===============================
```

---

### Layer 2: Interface Compliance Decision Engine Tests (`test_compliance_interface.py`)

Using `@patch` and `MagicMock`, this suite isolates `compliance_interface()` from physical SSH sockets. It evaluates the full state‑machine lifecycle, including fast‑path bypasses, remediation triggers, dry‑run safety gates, and post‑validation re‑polling.

#### Test Cases Covered:
1. **`test_compliance_interface_already_compliant`**: Simulates an interface matching NetBox intent (`is_up == should_be_up`). Asserts `mock_log.info` was called once, `mock_log.warning` was **never called**, `actions_taken` logged the compliance pass, and `initial_issues` remained empty.
2. **`test_compliance_interface_non_compliant_config_successful`**: Simulates an interface status mismatch (`Mismatched Interface State`) followed by successful remediation. Asserts warning log was called, the drift diff was stored in `initial_issues`, remediation summary was appended to `actions_taken`, and status resolved to `OperationalStatus.SUCCESS`.
3. **`test_compliance_interface_non_compliant_config_failed`**: Simulates an SSH/CLI failure during `configure_interface()`. Asserts the failure was captured under `critical_issues` and the overall execution was flagged as `FAILED_CONFIG`.
4. **`test_compliance_interface_dry_run`**: Patches `DRY_RUN = True`. Asserts drift was identified and logged, but `configure_interface()` was **never called**, and actions reflected `[DRY_RUN] Would Change Interface Status`.
5. **`test_compliance_interface_post_validation_successful`**: Simulates the complete closed‑loop cycle: initial check fails → remediation executes → `collect_device_state()` re‑polls → post‑check confirms compliance. Asserts post‑validation success was recorded in `actions_taken`.
6. **`test_compliance_interface_post_validation_failed`**: Simulates persistent drift where configuration was sent, but the re‑queried switch state still fails the operational check. Asserts status is set to `OperationalStatus.FAILED_VALIDATION` and a critical error is logged.
7. **`test_compliance_interface_empty`**: Evaluates behavior when no interfaces are declared in NetBox context (`{"interfaces": []}`). Asserts the module completes with zero issues and zero actions taken.

#### Excerpt:

![Interface Compliance Unit Tests Passed](screenshots/unit-test-code-compliance-interface.png)

```python
# tests/unit/compliance/switching/test_compliance_interface.py (Excerpt)

@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_non_compliant_config_successful(
    mock_check_interface, mock_build_interface, mock_configure_interface,
    mock_sesh, mock_context, mock_device_result, mock_log, mock_transport
):
    mock_build_interface.return_value = {}
    mock_check_interface.side_effect = [(False, ["Mismatched Interface State"]), (True, [])]
    mock_configure_interface.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Interface Configuration Successful"
    }

    result = compliance_interface(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log, mock_transport
    )

    mock_log.warning.assert_called_once()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("Interface Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value
```

#### Terminal Execution:

![Interface Compliance Unit Tests Passed](screenshots/unit-test-compliance-interface-passed.png)

```bash
$ PYTHONPATH=. pytest tests/unit/compliance/switching/test_compliance_interface.py -v
============================= test session starts ==============================
platform linux -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0 -- /home/rich/Documents/network-automation-engine-main/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/rich/Documents/network-automation-engine-main
collected 7 items

tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_already_compliant PASSED          [ 14%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_non_compliant_config_successful PASSED [ 28%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_non_compliant_config_failed PASSED     [ 42%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_dry_run PASSED                         [ 57%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_post_validation_successful PASSED    [ 71%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_post_validation_failed PASSED        [ 85%]
tests/unit/compliance/switching/test_compliance_interface.py::test_compliance_interface_empty PASSED                          [100%]

============================== 7 passed in 0.85s ===============================
```
### Continuous Integration Ready

The test framework is designed for CI/CD pipeline integration:

```yaml
# .github/workflows/test.yml (GitHub Actions Example)
name: Run Unit Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests with coverage                            <--------- Pytests 
        run: pytest tests/unit/ --cov=src --cov-report=xml
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
```
---

### Test Suite Execution Summary

| Test Suite | File Path | Scope & Boundary Scenarios Covered | Status | Execution Time |
| :--- | :--- | :--- | :---: | :---: |
| **Builder Tests** | `tests/unit/collectors/cli/test_build_interface.py` | Operational Genie parsing, compound L1/L2 logic, casing normalization, empty/None fallbacks, missing keys | **PASSED (6/6)** | 0.68s |
| **Compliance Tests** | `tests/unit/compliance/switching/test_compliance_interface.py` | State‑machine reconciliation, bypass logic, remediation push, dry‑run safety, closed‑loop post‑validation | **PASSED (7/7)** | 0.85s |
| **Total** | | **Comprehensive Offline Verification** | **13 / 13** | **1.53s** |

---

## Conclusion & Engineering Takeaways

This module demonstrates that network interface compliance is not just about running a `show run` and eyeballing the output. By decoupling data collection, normalization, decisioning, and remediation, this engine transforms interface hygiene from a manual, error-prone chore into a **deterministic, observable, and reversible software pipeline**.

Key architectural wins validated in this project include:
1. **Phantom Hardware Detection:** The engine doesn't just check status; it validates physical existence. If NetBox declares an interface that the hardware doesn't support (e.g., `GigabitEthernet1/0` on an Ethernet-only chassis), Gate 1 short-circuits the check, preventing catastrophic command execution errors.
2. **Zero-Touch Safety:** The `DRY_RUN` gating ensures that change-advisory boards (CABs) can review exact, rendered CLI payloads and projected state changes before any socket transmission occurs.
3. **Closed-Loop Guarantees:** Pushing a config via Netmiko is not proof of compliance. Re-querying the device via Genie and re-running the diff engine guarantees the hardware actually accepted and applied the change, catching silent SFP or transceiver faults.
4. **Resilient Exception Handling:** A broken Jinja2 template doesn't crash the pipeline. The `try/except` boundary catches the `TemplateSyntaxError`, streams it to Splunk as an `ERROR` event for immediate triage, and allows the audit of remaining interfaces to continue uninterrupted.

### Next Steps & Future Enhancements
To further evolve this automation engine, the following enhancements are planned:
- **Multi-Vendor Abstraction:** Leverage Genie's vendor-agnostic parsing to extend this exact same compliance logic to Arista (EOS) and Juniper (Junos) platforms without rewriting the core diff engine.
- **Advanced L2 Policy Validation:** Expand the compliance checks to validate Link Aggregation (LACP/EtherChannel) member states, speed/duplex mismatches, and dynamic MAC address learning limits.
- **CI/CD Pipeline Integration:** Embed the existing 13-case Pytest suite into GitHub Actions to automatically block Pull Requests that introduce regressions to the compliance logic or Jinja2 templates.

---

### Return to Main Repository

This module is part of a broader Network Automation Engine portfolio. 

**Explore other modules:**
- [Trunk Port Compliance & Remediation](../trunk-ports/)
- [F5 BIG-IP LTM Cloud Load Balancing](../f5-big-ip-ltm-lab/)

**[Return to Main Repository README](../README.md)**
