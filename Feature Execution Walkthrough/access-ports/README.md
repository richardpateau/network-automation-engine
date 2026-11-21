# Access Port Compliance & Remediation

## Overview

The Access Port Compliance module is part of the network automation engine. It validates Cisco switch access-port configurations against the expected network configuration stored in NetBox.

The module identifies access ports with incorrect VLAN assignments or operational modes, reports configuration drift, and can automatically remediate non-compliant interfaces.

The implementation uses NetBox as the Source of Truth (SoT), Genie for parsing device state, and Netmiko for device configuration.

## Objectives

- Retrieve expected access-port configurations from NetBox.
- Collect actual switchport configurations from Cisco devices.
- Identify access ports with incorrect VLAN assignments.
- Detect interfaces operating in the wrong mode.
- Automatically configure non-compliant access ports.
- Validate configuration changes after remediation.
- Record compliance results and remediation activity through structured logging.
- Support dry-run execution without modifying device configurations.

## Architecture

The access-port compliance workflow consists of five main components:

| Component | Responsibility |
|---|---|
| NetBox Inventory | Supplies expected access interfaces and VLAN assignments. |
| Genie Collector | Collects and parses actual switchport configurations. |
| Access Builder | Normalizes collected switchport data. |
| Compliance Checker | Compares expected and actual interface configurations. |
| Remediation Engine | Applies configuration changes and supports post-remediation validation. |

## Workflow

```text
             NetBox
                |
                v
       Expected Access Ports
                |
                v
        Genie Device Collector
                |
                v
          build_access()
                |
                v
          check_access()
                |
          +-----+-----+
          |           |
       Compliant   Non-Compliant
          |           |
          v           v
       Log Result   DRY_RUN?
                      |
                 +----+----+
                 |         |
                Yes        No
                 |         |
                 v         v
             Log Planned  configure_access()
             Remediation      |
                              v
                       Collect New State
                              |
                              v
                       Post-Validation
                              |
                              v
                       Record Final Result
```

## 1. Source of Truth — NetBox

NetBox provides the expected access-port configuration.

The inventory builder retrieves device interfaces and checks their configured mode and untagged VLAN.

Example inventory data:

```python
{
    "access_ports": [
        {
            "access_interface": "Ethernet0/0",
            "access_vlan": 10
        },
        {
            "access_interface": "Ethernet0/1",
            "access_vlan": 20
        }
    ]
}
```

Access ports are identified using the NetBox interface mode and untagged VLAN:

```python
if (
    device_interface.mode
    and device_interface.mode.value == "access"
    and device_interface.untagged_vlan
):
    config_data[host_ip]["access_ports"].append(
        {
            "access_interface": device_interface.name,
            "access_vlan": device_interface.untagged_vlan.vid,
        }
    )
```

This allows the automation engine to use NetBox as the authoritative reference for expected access-port assignments.

## 2. Device State Collection

The collector retrieves actual switchport information from the Cisco device.

Genie provides structured output that is passed to the `build_access()` function.

The builder normalizes the collected information into a consistent dictionary.

Example normalized output:

```python
{
    "gigabitethernet0/0": {
        "access_interface": "gigabitethernet0/0",
        "operational_mode": "static access",
        "access_vlan": "98"
    },
    "gigabitethernet0/1": {
        "access_interface": "gigabitethernet0/1",
        "operational_mode": "static access",
        "access_vlan": "20"
    }
}
```

Trunk interfaces are excluded from the access-port compliance results.

## 3. Compliance Validation

The `check_access()` function compares the expected interface configuration against the normalized device state.

The checker validates:

- Interface existence.
- Operational mode.
- Access VLAN assignment.

Example expected configuration:

```python
{
    "access_interface": "gigabitethernet0/0",
    "access_vlan": 98
}
```

Example actual configuration:

```python
{
    "gigabitethernet0/0": {
        "access_interface": "gigabitethernet0/0",
        "operational_mode": "static access",
        "access_vlan": "98"
    }
}
```

The checker normalizes VLAN values to strings before comparison.

Possible compliance results include:

| Condition | Result |
|---|---|
| Interface exists, correct access mode, correct VLAN | Compliant |
| Interface missing from access-port results | Non-compliant |
| VLAN assignment differs from NetBox | Non-compliant |
| Interface operating in trunk mode | Non-compliant |

## 4. Automated Remediation

When configuration drift is detected, the compliance engine records the issue and invokes `configure_access()` when dry-run mode is disabled.

The remediation function receives:

- Device session.
- Expected access-port configuration.
- Logger.
- Device management IP.
- Transport type.

The remediation process is responsible for applying the required interface configuration.

Example Cisco IOS configuration:

```cisco
interface Ethernet0/0
 switchport mode access
 switchport access vlan 10
```

Successful remediation is recorded in the device results.

Failed remediation updates the device status to `FAILED_CONFIG` and records the failure as a critical issue.

## 5. Dry-Run Mode

The module supports a dry-run mode through the project-wide `DRY_RUN` setting.

When enabled:

- Compliance checks still execute.
- Configuration drift is identified.
- Planned remediation is recorded.
- No configuration commands are sent to the device.

Example action:

```text
[DRY_RUN] Would Configure Access Port |
Interface: Ethernet0/0 |
VLAN: 10
```

This allows configuration changes to be reviewed before they are applied.

## 6. Post-Remediation Validation

After successful remediation, the module collects device state again.

The updated state is normalized using `build_access()` and compared against the expected configuration using `check_access()`.

The final result is recorded as either:

- `SUCCESS` — the interface now matches the expected configuration.
- `FAILED_VALIDATION` — the interface still does not meet the expected configuration.

This provides a verification step instead of assuming that a successful configuration command guarantees compliance.

## 7. Logging and Reporting

The compliance engine records structured events for access-port validation and remediation.

Logged fields include:

| Field | Description |
|---|---|
| `device_ip` | Device management IP address |
| `event_type` | Compliance event classification |
| `component` | Component responsible for the event |
| `protocol` | Access-interface compliance identifier |
| `transport` | Device connection transport |
| `interface` | Interface being evaluated |
| `vlan_id` | Expected access VLAN |
| `compliant` | Compliance result |
| `failures_count` | Number of detected failures |
| `failures` | Detailed compliance failures |
| `status` | Execution status |
| `detail` | Event description |

The device result maintains three important collections:

- `initial_issues` — configuration drift detected before remediation.
- `actions_taken` — successful actions and planned dry-run actions.
- `critical_issues` — remediation or post-validation failures.

## 8. Unit Testing

The access-port functionality includes pytest coverage for the builder and compliance workflow.

### Builder Tests

| Test | Purpose |
|---|---|
| `test_build_access_valid_path` | Validates parsing of Genie switchport output. |
| `test_build_access_ingore_trunk` | Ensures trunk interfaces are excluded. |
| `test_build_access_mixed` | Tests mixed access and trunk interface data. |
| `test_build_access_no_vlan` | Validates handling of an access interface without a VLAN value. |
| `test_build_access_empty` | Validates empty input handling. |
| `test_build_access_no_dict` | Validates input without switchport data. |

### Compliance Tests

| Test | Purpose |
|---|---|
| `test_compliance_access_already_compliant` | Confirms compliant interfaces are not remediated. |
| `test_compliance_access_non_compliant_config_successful` | Tests successful remediation. |
| `test_compliance_access_non_compliant_config_failed` | Tests failed remediation handling. |
| `test_compliance_access_dry_run` | Confirms no configuration is applied during dry-run execution. |
| `test_compliance_access_post_validation_successful` | Tests successful post-remediation validation. |
| `test_compliance_access_post_validation_failed` | Tests failed post-remediation validation. |
| `test_compliance_access_empty` | Tests behavior when no expected access ports exist. |

### Running the Tests

From the project root:

```bash
PYTHONPATH=. pytest tests/unit/collectors/cli/test_build_access.py -v
```

Run the compliance tests:

```bash
PYTHONPATH=. pytest tests/unit/compliance/switching/access -v
```

Run the complete test suite:

```bash
PYTHONPATH=. pytest -v
```

## Technologies

- **Python** — Automation and compliance logic.
- **NetBox** — Network Source of Truth and inventory.
- **Netmiko** — Network device connectivity and configuration.
- **Genie** — Structured network device output parsing.
- **Jinja2** — Configuration template rendering.
- **pytest** — Automated testing and validation.

## Design Considerations

The module separates inventory retrieval, device-state collection, normalization, compliance validation, and remediation.

This separation makes individual components easier to test and maintain while allowing the compliance engine to follow a consistent workflow.

The use of post-remediation validation helps ensure that configuration changes achieve the intended result rather than relying solely on command execution status.
