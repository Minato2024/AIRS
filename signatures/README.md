# AIRS Signature Rules

This directory contains the on-disk rule set for AIRS signature-based detection.

## Supported Format

Rules are loaded recursively from `*.json` files under this folder.

Each JSON file may contain either:

```json
{
  "rules": [
    {
      "id": "SIG-001",
      "name": "Example Rule",
      "pattern": "wget.*\\.sh",
      "attack_type": "malware",
      "threat_level": "critical"
    }
  ]
}
```

or a raw JSON array of rule objects.

## Required Fields

- `id`
- `name`
- `pattern`
- `attack_type`
- `threat_level`

## Optional Fields

- `description`
- `confidence`
- `enabled`
- `fields`
- `event_types`
- `protocols`
- `honeypot_types`
- `dest_ports`
- `source_ports`
- `require_meta_keys`
- `match_mode`
- `tags`
- `mitre_mappings`

## Field Matching

`fields` controls which parts of the incoming honeypot event are searched.

Supported values:

- `command`
- `payload`
- `username`
- `password`
- `event_type`
- `protocol`
- `source_ip`
- `source_port`
- `dest_port`
- `session_id`
- `honeypot_type`
- `meta`
- `meta_json`
- `meta.<key>`

If `fields` is omitted, AIRS defaults to:

```json
["command", "payload", "username", "password", "event_type"]
```

## Context Filters

Rules can be limited to specific traffic context without encoding everything into one regex.

- `event_types`: only evaluate for matching event types
- `protocols`: only evaluate for matching transport/application protocols
- `honeypot_types`: scope a rule to specific honeypot sources
- `dest_ports` and `source_ports`: restrict by port
- `require_meta_keys`: require metadata keys to exist before evaluating

## Match Modes

- `any`: the `pattern` is evaluated as a single regex
- `all`: split `pattern` on `&&` and require every regex fragment to match

## Notes

- Disabled rules (`"enabled": false`) are skipped.
- Rules are loaded recursively, so you can organize them by category.
- Higher severity and higher confidence rules are evaluated first.
