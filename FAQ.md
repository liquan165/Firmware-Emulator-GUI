# FAQ / Troubleshooting

## Q: Why can't I ping the guest IP in NAT mode?
In QEMU `-netdev user` NAT mode, ICMP is often not forwarded. Use hostfwd ports (SSH/HTTP) instead.

## Q: SSH works in cmd but not in Python libraries (Paramiko)?
Old guests (e.g., Debian squeeze) may only offer legacy algorithms (ssh-rsa/ssh-dss, old ciphers).  
This project avoids Paramiko and uses Windows OpenSSH with explicit compatibility flags.

## Q: I see "Bad permissions" for private keys
Windows OpenSSH enforces strict ACL checks. Generate keys using:
`C:\Windows\System32\OpenSSH\ssh-keygen.exe`

## Q: After injecting key, login still fails
Check on the guest:
- `/root/.ssh` is 700
- `/root/.ssh/authorized_keys` is 600
- key line is valid (no duplicated prefix like `ssh-rsa ssh-rsa ...`)

Also verify sshd config:
- `PubkeyAuthentication yes`
- `PermitRootLogin yes` (if using root)
