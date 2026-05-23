# Kernel UAF (Use-After-Free) Detector Module

Kernel module for detecting temporal memory bugs inside Linux kernel space using slab cache validation, canary protection, RCU delayed freeing, and runtime integrity checks.

This project demonstrates how production-grade kernels detect:

- dangling pointers
- use-after-free
- double free
- freelist corruption
- stale memory access
- race-triggered corruption

---

# Features

- custom slab allocator
- SLAB_POISON support
- SLAB_RED_ZONE support
- canary validation
- runtime UAF detection
- double-free detection
- RCU delayed reclamation
- freelist poisoning simulation
- timer-based integrity checks
- procfs statistics reporting
- trace_printk observability
- stack trace generation
- standalone external module

---

# Project Files

| File | Purpose |
|------|----------|
| slab_uaf_detector.c | Main kernel module |
| Makefile | Kernel module build |
| .gitignore | Ignore kernel build artifacts |

---

# Build

```bash
make
```

---

# Load Module

```bash
sudo insmod slab_uaf_detector.ko
```

---

# Observe Runtime Logs

Kernel log:

```bash
dmesg -w
```

Trace events:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Runtime statistics:

```bash
cat /proc/slab_uaf_stats
```

---

# Unload Module

```bash
sudo rmmod slab_uaf_detector
```

---

# Internal Design

The module creates a dedicated slab cache:

```c
kmem_cache_create(
    "uaf_cache",
    sizeof(struct uaf_object),
    0,
    SLAB_POISON | SLAB_RED_ZONE,
    uaf_ctor);
```


# Build Module

```bash
make
```

---

# Sign Kernel Module

```bash
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \
sha256 \
~/kernel_keys/MOK.key \
~/kernel_keys/MOK.crt \
slab_uaf_detector.ko
```

---

# Insert Module

```bash
sudo insmod slab_uaf_detector.ko
```

---

# Verify Module Loaded

```bash
lsmod | grep slab_uaf_detector
```

---

# View Runtime Statistics

```bash
cat /proc/slab_uaf_stats
```

You will see runtime statistics such as:

- allocations
- frees
- UAF detects
- corruptions

---

# Enable Kernel Trace Events

```bash
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
```

---

# Observe Live Trace Output

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

# Remove Module

```bash
sudo rmmod slab_uaf_detector
```

---

# Verify Module Removed

```bash
lsmod | grep slab_uaf_detector
```

---

# Check Recent Kernel Logs

```bash
dmesg | tail -50
```


Each object contains:

- start canary
- metadata
- RCU head
- linked-list tracking
- end canary

---

# Canary Validation

Every object is surrounded by guard values:

```c
#define CANARY_VALUE 0xDEADBEEF
```

Validation occurs during:

- allocation
- access
- free
- timer scans

---

# Use-After-Free Detection

The detector validates:

```c
if (obj->freed)
```

If true:

- stack trace is generated
- trace event is emitted
- runtime counter increments

---

# RCU Delayed Freeing

Objects are reclaimed asynchronously:

```c
call_rcu(&obj->rcu, rcu_free_callback);
```

This simulates real kernel delayed reclamation behavior.

---

# Poisoning Pattern

Freed memory is overwritten using:

```c
memset(obj, 0xA5, sizeof(*obj));
```

The pattern:

```text
0xA5A5A5A5
```

helps expose stale pointer access.

---

# Example Runtime Output

```text
ALLOC id=1
USE_AFTER_FREE id=1
FREE id=-1515870811
```

The corrupted FREE id:

```text
-1515870811
```

corresponds to:

```text
0xA5A5A5A5
```

showing successful poisoning after reclaim.

---

# Procfs Statistics

```bash
cat /proc/slab_uaf_stats
```

Example:

```text
=== UAF Detector Stats ===
Allocations : 1
Frees       : 1
UAF Detects : 1
Corruptions : 0
```

---

# Educational Goals

This project demonstrates:

- slab allocator internals
- temporal memory safety
- RCU synchronization
- kernel debugging
- exploit mitigation concepts
- memory corruption detection
- Linux kernel observability

---

# Intended Audience

Useful for:

- kernel developers
- cybersecurity engineers
- Linux internals learners
- exploit researchers
- systems programmers

---

# License

GPL
