---
publish: true
created: 2026-10-03T08:40:24.747Z
modified: 2026-10-03T08:40:24.747Z
---

# Windows

**DACL** -  Discretionary Access Control Lists.

Here are the basic, simple rights.

- **N** - No access
- **F** - Full access
- **M** - Modify access
- **RX** - Read and execute access
- **R** - Read-only access
- **W** - Write-only access
- **D** - Delete access

inherited rights:

- **(I)** - Inherit. ACE inherited from the parent container.
- **(OI)** - Object inherit. Objects in this container inherits this ACE. Applies only to directories.
- **(CI)** - Container inherit. Containers in this parent container inherits this ACE. Applies only to directories.
- **(IO)** - Inherit only. ACE inherited from the parent container, but doesn't apply to the object itself. Applies only to directories.
- **(NP)** - Don't propagate inherit. ACE inherited by containers and objects from the parent container, but doesn't propagate to nested containers. Applies only to directories.

The rest can be found here:
<https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls#remarks>
