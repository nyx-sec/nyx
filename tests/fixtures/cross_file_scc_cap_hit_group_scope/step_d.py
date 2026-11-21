import subprocess
from step_a import step_a


def step_d(x):
    # Back-edge closes the SCC: {step_a, step_b, step_c, step_d}.
    if x == "recursive":
        step_a(x)
    # Sink at the far end of the cycle.  The param-to-sink fact must
    # propagate backwards through step_c, step_b, and finally step_a
    # so that the caller in server.py sees the transitive flow.
    subprocess.run(x, shell=True)
