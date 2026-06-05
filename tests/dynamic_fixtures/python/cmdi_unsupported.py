"""Command injection — unsupported fixture.

Low-confidence finding that produces Unsupported(ConfidenceTooLow).
Expected verdict: Unsupported(ConfidenceTooLow)
"""
import subprocess


def process_request(cmd):
    """Vulnerable function used in unsupported-confidence test."""
    subprocess.run(cmd, shell=True)
