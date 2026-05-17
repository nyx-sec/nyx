"""Phase 04 (Track J.2) — Python Jinja2 SSTI vuln fixture.

The function pulls a template body off the request and pipes it
straight into `jinja2.Template(...).render()` without sandboxing or
expression filtering, so an attacker who controls the body reaches the
expression evaluator and can render arbitrary expressions.
"""
from jinja2 import Template


def run(body: str) -> str:
    template = Template(body)
    return template.render()
