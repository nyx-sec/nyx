# Fixture: spec derived via FromRuleNamespace (AST pattern `py.cmdi.os_system`
# without a taint flow).
import os

def run_user_command(user_arg):
    os.system(user_arg)
