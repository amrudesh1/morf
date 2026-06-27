# Seccomp Sandboxing

## Overview
This directory contains seccomp (secure computing mode) profiles for sandboxing external tool execution in MORF.

## Files

### seccomp-apktool.json
Seccomp profile for apktool, apkanalyzer, and other Java-based tools.

**Allowed Syscalls:**
- File operations (read, write, open, close, etc.)
- Process management (fork, exec, wait, etc.)
- Memory management (mmap, mprotect, etc.)
- Network operations (socket, bind, connect, etc.)
- System information (getpid, getuid, etc.)

**Blocked Syscalls:**
- System administration (mount, umount, etc.)
- Kernel modules (init_module, delete_module)
- Debugging (ptrace, kexec_load)
- Other potentially dangerous syscalls

## Usage

### Docker Compose
The seccomp profile is automatically applied via `docker-compose.yml`:

```yaml
security_opt:
  - seccomp:./seccomp/seccomp-apktool.json
```

### Docker Run
```bash
docker run --security-opt seccomp=./seccomp/seccomp-apktool.json morf:latest
```

### Kubernetes
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: morf
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: seccomp/seccomp-apktool.json
```

## Testing

To test that the seccomp profile works:

```bash
# Run container with seccomp profile
docker run --security-opt seccomp=./seccomp/seccomp-apktool.json morf:latest

# Verify tools still work
docker exec <container_id> java -jar /app/tools/apktool.jar --version
```

## Customization

If you need to add or remove syscalls:

1. Edit `seccomp-apktool.json`
2. Test thoroughly
3. Document changes
4. Update this README

## Troubleshooting

### Tools Fail with "Operation not permitted"
- Check if required syscall is in the profile
- Add syscall to profile if necessary
- Test thoroughly after changes

### Performance Issues
- Seccomp has minimal performance impact
- If issues occur, check syscall filtering
- Consider if syscall is necessary

## References
- [Docker Seccomp Documentation](https://docs.docker.com/engine/security/seccomp/)
- [Seccomp Man Page](https://man7.org/linux/man-pages/man2/seccomp.2.html)

