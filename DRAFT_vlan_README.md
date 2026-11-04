# VLAN Compliance & Automated Remediation

## Overview

This walkthrough demonstrates an end-to-end **intended-state VLAN compliance workflow** built into the Network Automation Engine.

NetBox serves as the source of truth for VLAN configuration. The automation engine collects the current VLAN state from network devices, compares it against the intended configuration, detects configuration drift, and generates and applies remediation commands when necessary.

The defining design principle of this feature is **trust through verification**: successful command execution alone is never treated as proof of compliance. After every remediation, the engine re-collects device state and re-runs the compliance check, so the workflow only reports success when the device's *actual* configuration matches the *intended* configuration.

Every stage — collection, compliance verdict, remediation action, and post-validation result — emits a structured event to Splunk, producing a queryable audit trail suitable for change records and incident forensics.

**Tech stack:** Python · NetBox (REST) · Netmiko · Genie/PyATS parsers · Jinja2 · Splunk HTTP Event Collector · pytest

## Automation Workflow

```
NetBox (source of truth)
        │
        ▼
Inventory Processing ──► State Collection ──► Compliance Check
     (NetBox API)       (Netmiko + Genie)    (actual vs. intended)
                                                   │
                            ┌──────────────────────┴──────────────────────┐
                         Compliant                                  Non-Compliant
                            │                                                  │
                            │                                    Jinja2 Remediation
                            │                                       (apply config)
                            │                                                  │
                            │                                        Post-Validation
                            │                                     (re-collect and
                            │                                      re-check state)
                            └──────────────────────┬───────────────────────────┘
                                                   ▼
                                         Splunk Event Logging
```

1. **Source of Truth:** Retrieve intended VLAN configuration from NetBox.
2. **Inventory Processing:** Load VLAN configuration into the automation context.
3. **State Collection:** Collect existing VLAN information from the network device using Netmiko and Genie.
4. **Compliance Checking:** Compare the actual VLAN configuration against the intended configuration.
5. **Remediation:** Generate configuration commands using a Jinja2 template and apply them to the device.
6. **Post-Validation:** Collect device state again and verify that remediation resolved the detected drift.
7. **Event Logging:** Forward configuration and validation events to Splunk.
8. **Unit Testing:** Test VLAN collection and compliance logic using pytest.

## 1. NetBox — Source of Truth

NetBox stores the intended VLAN configuration used by the automation engine.

The VLAN configuration is retrieved and passed into the automation context, providing the expected state against which the device configuration is evaluated. Keeping intent in NetBox — rather than in scripts or spreadsheets — means the network team manages VLANs through their normal workflow and automation inherits it automatically.

![NetBox VLAN Source of Truth](screenshots/vlans-netbox-source-of-truth.png)

## 2. Python Inventory Configuration

The retrieved NetBox data is processed into the structure consumed by the automation engine.

The inventory configuration provides the expected VLAN ID and name to the compliance workflow.

![Python VLAN Inventory Configuration](screenshots/vlans-python-inventory-config.png)

The resulting VLAN data is also printed for verification before compliance processing.

![Python VLAN Inventory Output](screenshots/vlans-python-inventory-config-print-vlan.png)

## 3. VLAN State Collection and Parsing

The automation engine connects to the network device and collects its current VLAN configuration.

Netmiko executes the device command, while Genie parses the CLI output into structured data. Using a dedicated parser instead of raw-text matching makes the comparison resilient to formatting differences across IOS versions.

The `build_vlan()` function processes the collected data into a normalized dictionary containing VLAN IDs and names. Normalizing both intended and actual state into the same structure keeps the compliance logic simple and testable.

This normalized state is passed to the compliance checker.

## 4. VLAN Compliance Checking

The compliance checker compares the intended VLAN configuration against the collected device state.

It evaluates two conditions: whether the expected VLAN exists, and whether its configured name matches the source of truth. A VLAN that exists with the wrong name is treated as drift — not a pass.

### Compliance Check — Non-Compliant State

The following example demonstrates a device missing the expected VLAN.

![VLAN Compliance Check Failure](screenshots/check-vlan-terminal-output-fail-no-vlan.png)

The compliance checker identifies the missing VLAN and reports the configuration drift.

### Compliance Check — Compliant State

When the device configuration matches the intended state, the checker reports compliance without requiring remediation.

![VLAN Compliance Check Success](screenshots/check-vlan-terminal-output-pass.png)

## 5. Automated VLAN Remediation

When a compliance failure is detected, the automation engine generates the required configuration commands using a Jinja2 template.

Template-driven rendering separates *what should be configured* from *how it is rendered*, so changes to command syntax don't require touching the compliance logic. The rendered commands are passed to the device configuration function, which applies the intended VLAN configuration.

![VLAN Jinja2 Template](screenshots/vlan-jinja-2-template.png)

The remediation function handles the configuration process and records its execution result.

![VLAN Configuration Function](screenshots/configure-vlan-code-breakdown-visio.png)

## 6. Post-Remediation Validation

Successful command execution alone does not establish that the device is compliant — commands can be accepted by a CLI yet fail to produce the intended operational state.

After remediation, the automation engine collects the device state again and runs the compliance check against the updated configuration.

If the expected VLAN is present and its name matches the source of truth, post-validation succeeds. If the configuration still does not match, the workflow records a validation failure rather than reporting a false positive.

![Splunk Post-Validation Success](screenshots/splunk-post-validation-successful.png)

## 7. Splunk Event Logging

The VLAN workflow forwards structured events to Splunk, providing visibility into compliance results, configuration actions, and post-remediation validation. Because each run emits discrete, timestamped events, operators can search by device and VLAN to reconstruct exactly what the automation saw, decided, and changed.

The following screenshots demonstrate different execution scenarios.

| Scenario | Evidence |
|---|---|
| VLAN already compliant | `screenshots/splunk-vlan-configuration-already-configured.png` |
| VLAN configuration non-compliant | `screenshots/splunk-vlan-configuration-non-compliant.png` |
| VLAN successfully configured | `screenshots/splunk-vlan-configured-successfully.png` |
| Successful post-validation | `screenshots/splunk-vlan-post-validation-success.png` |

These events provide an audit trail of the automation process and help identify configuration failures and unresolved compliance issues.

## 8. Unit Testing

Pytest is used to validate the VLAN state-building and compliance functions independently of live network devices. Device interaction is mocked at the boundary, so the business logic is exercised deterministically and the suite runs in CI without a lab.

### VLAN State Builder Tests

The collector tests verify that VLAN data is correctly parsed and normalized, including empty input, missing VLAN names, and invalid VLAN identifiers.

![VLAN Builder Unit Tests](screenshots/test-build-vlan-passed.png)

### VLAN Compliance Tests

The compliance tests cover both the happy path and the failure paths that matter operationally:

- Already-compliant VLAN configuration.
- Successful VLAN remediation.
- Failed VLAN remediation.
- Dry-run behavior.
- Successful post-remediation validation.
- Failed post-remediation validation.
- Empty VLAN configuration.

![VLAN Compliance Unit Tests](screenshots/test-compliance-vlan-passed.png)

## 9. End-to-End Demonstration

The accompanying video demonstrates the VLAN automation workflow, including compliance checking, configuration remediation, and validation.

**Video:** `videos/vlan-automation.mp4`

---

## Results

The VLAN automation feature demonstrates a complete configuration compliance lifecycle:

- NetBox-driven intended configuration.
- Automated device state collection and parsing.
- Configuration drift detection.
- Jinja2-based configuration generation.
- Automated VLAN remediation.
- Post-remediation compliance validation.
- Centralized Splunk event logging.
- Unit testing with pytest.

The result is a repeatable VLAN compliance workflow that detects configuration drift, attempts remediation, and verifies the resulting device state rather than relying solely on successful command execution.

## Design Decisions

| Decision | Rationale |
|---|---|
| NetBox as single source of truth | Intent lives where the network team already works; no parallel config database to fall out of sync. |
| Parse to structured data (Genie) before comparing | Comparison operates on normalized dicts, not string matching against CLI output. |
| Name mismatch counts as drift | A VLAN present with the wrong name is a real misconfiguration, not a pass. |
| Re-collect and re-check after remediation | Distinguishes "commands were accepted" from "device is actually compliant." |
| Templated config generation (Jinja2) | Command syntax changes don't require modifying compliance logic. |
| Structured Splunk events per stage | Produces a searchable audit trail for change evidence and troubleshooting. |
| Mocked-device unit tests | Logic is verified in CI without depending on lab hardware availability. |
