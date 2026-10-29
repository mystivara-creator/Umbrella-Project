# Umbrella–CoreFlow interface proposals

This directory contains **design examples only**. No kernel API, daemon endpoint, or stable ABI is implemented by the foundation package.

Prefer existing Linux and Android interfaces. If an Umbrella-specific contract becomes necessary, first document:

- Feature identity, version, semantics and detection.
- Read and write permissions, bounds, and failure behavior.
- Compatibility negotiation and unsupported-feature handling.
- Read-back, measurement, contention avoidance and rollback limitations.
- Security threat model and expected SELinux policy.

An example JSON data shape is provided solely for discussion. Do not assume it is machine-readable kernel output.
