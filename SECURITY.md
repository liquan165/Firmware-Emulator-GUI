# Security Policy

## Supported Versions
This project is intended for local lab usage on Windows. No formal support guarantees are provided.

## Security Considerations

- This tool launches QEMU guests and can upload/extract files into the guest.
- The SSH Key Wizard appends a public key to the guest user's `~/.ssh/authorized_keys`.
- noVNC is downloaded from GitHub and verified by pinned SHA256.

## Reporting a Vulnerability
If you discover a security issue, please open a private report by creating a GitHub Security Advisory or contact the maintainer via email (add your email here).
