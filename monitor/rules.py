# monitor/rules.py
# Define risk rules and constants

MAX_SUBPROCESS_COUNT = 50

RISK_RULES = {
    "high": [
        # ========================
        # Sensitive File Access
        # ========================
        # Core system configuration files
        (r'openat\(.*"/etc/(passwd|shadow|sudoers|sudoers\.d/.*|group|hosts|ld\.so\.preload)"',
         "❌ Unauthorized access to core system configuration files"),
        (r'openat\(.*"/etc/(cron\..*|sysctl\.conf|security/access\.conf|apparmor/.*)"',
         "❌ Unauthorized access to system security policy files"),
        # User credentials related
        (r'openat\(.*"/home/.*/(\.ssh/(id_rsa|authorized_keys|config)|\.aws/credentials|\.gnupg/.*)"',
         "❌ Access to user keys or cloud credentials"),
        (r'openat\(.*"/root/\.ssh/.*"',
         "❌ Access to root user SSH files"),
        # Kernel and memory
        (r'openat\(.*"/(proc/kcore|sys/kernel/debug/.*|dev/(mem|kmem))"',
         "❌ Unauthorized access to kernel or physical memory"),
        (r'openat\(.*"/proc/self/(mem|exe|fd/.*)"',
         "❌ Process memory or file descriptor operations"),

        # ========================
        # File Write and Tampering
        # ========================
        # Sensitive file write mode detection
        (r'openat\(.*"(/etc/passwd|/etc/shadow|/var/spool/cron/.*)".*O_WRONLY',
         "❌ Opening sensitive file in write mode"),
        (r'write\(\d+, ".*(root:/bin/bash|nobody:/bin/sh).*"',
         "❌ Detected unauthorized user addition (passwd format)"),
        (r'write\(\d+, ".*\* \* \* \* \* .*"',
         "❌ Writing malicious cron job (crontab syntax)"),
        # Log tampering
        (r'(unlink|rename)\(.*"/var/log/(auth\.log|secure|btmp)"',
         "❌ Deleting or renaming system logs"),
        (r'ftruncate\(\d+, 0\).*"/var/log/.*"',
         "❌ Clearing log file contents"),

        # ========================
        # Network Connection Risks (All network access is considered high risk)
        # ========================
        (r'(connect\(.*sin_port=htons\(\d+\)|socket\(AF_INET, SOCK_STREAM, 0\)|sendto\(.*|recvfrom\(.*)',
         "❌ Detected network access behavior"),

        # ========================
        # Process and Kernel Level Attacks
        # ========================
        (r'(init_module|finit_module|delete_module)\(',
         "❌ Kernel module load/unload (Rootkit risk)"),
        (r'ptrace\(.*PID=\d+.*uid=0',
         "❌ Tracing high-privilege processes (e.g., root)"),
        (r'write\(\d+, .*offset=0x[0-9a-f]+.*/proc/self/mem',
         "❌ Process memory tampering (Shellcode injection)"),

        # ========================
        # Container and Virtualization Escape
        # ========================
        (r'openat\(.*"/var/run/docker\.sock"',
         "❌ Access to Docker daemon socket (container escape)"),
        (r'openat\(.*"/proc/(mounts|self/ns/.*)"',
         "⚠️ Probing container/namespace environment"),

        # ========================
        # Defense Bypass Scenarios
        # ========================
        (r'openat\(.*"(\.\./)+etc/passwd"',
         "❌ Directory traversal attack attempt"),
        (r'openat\(.*"/tmp/.*\.(so|sh|py|elf)".*O_CREAT',
         "⚠️ Creating executable file in temporary directory"),
        (r'execve\("/bin/sh", \["sh", "-c", ".*"\]', "❌ os.system() call detected"),

    ],
    "medium": [
        (r'mount\(', "⚠️ Mount operation"),
        (r'openat\(.*"/etc/nginx/nginx\.conf"', "⚠️ Reading web server configuration"),
        (r'connect\(.*sin_port=htons\(53\)', "⚠️ Using DNS protocol (possible covert communication)")
    ],
    "low": [
        # Detect all print() output (logged via stdout write)
        (r'write\(1, .*', "📝 Detected print() output")
    ]
}
