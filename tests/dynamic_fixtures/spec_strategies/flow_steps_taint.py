# Fixture: spec derived via FromFlowSteps (taint flow with explicit source/sink).
import os

def handle_request(payload):
    cmd = payload
    os.system(cmd)
