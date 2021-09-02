# Resource Manager

This is a simple VM manager for use with the Gunyah Hypervisor.

> See https://github.com/quic/gunyah-hypervisor for additional documentation.

The Resource Manager is used as the *Root VM* and acts as an extension of the hypervisor. It provides the functionality to create the primary VM (HLOS) and any other static boot-time configuration or partitioning as required.

The Resource Manager provides a run-time service for secure dynamic VM loading and management. It provides APIs for creating and destroying VMs, secure memory management and sharing/lending memory between VMs, and setup of inter-VM communication.

The Resource Manager is built as a bare metal VM with musl libc and requires the [Gunyah libc Runtime](https://github.com/quic/gunyah-c-runtime).

## Limitations

This release of the Resource Manager is limited to setting up a primary VM. Future releases will provide the ability to load and manage secondary VMs.

## License

SPDX-License-Identifier: BSD-3-Clause

See [LICENSE](LICENSE) for the full license text.
