"""Positive control: verify the escape-detection mechanism itself.

Writes to /proc/sysrq-trigger, which requires CAP_SYS_ADMIN. This fixture
is expected to SUCCEED (print NYX_ESCAPE_SUCCESS) when run in a privileged
container (--cap-add=SYS_ADMIN) and to FAIL when run with --cap-drop=ALL.

CI usage (escape-positive-control job):
    Run under a container started with --cap-add=SYS_ADMIN.
    Assert NYX_ESCAPE_SUCCESS appears in output.
    If it does NOT appear, the test mechanism is broken or the capability
    was not granted, and the CI job fails.

Normal escape suite: this fixture is NOT included. The positive control test
(positive_control_cap_sys_admin in dynamic_sandbox_escape.rs) is #[ignore]d
and only un-ignored in the dedicated escape-positive-control CI job.
"""
import sys

try:
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("h")  # 'h' = print help, harmless
    print("NYX_ESCAPE_SUCCESS: CAP_SYS_ADMIN active, wrote to /proc/sysrq-trigger")
    sys.exit(0)
except (PermissionError, OSError) as e:
    print(f"BLOCKED: CAP_SYS_ADMIN not present: {e}", file=sys.stderr)
    sys.exit(1)
