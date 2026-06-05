"""Phase 04 (Track J.2) — Python Jinja2 benign control fixture.

The function escapes the body as plain text before handing it to a
fixed Jinja2 template that never interpolates the user-controlled
value, so even an SSTI-shaped payload cannot reach the evaluator.
"""
from jinja2 import Template


def run(body: str) -> str:
    safe = body.replace("{", "&#123;").replace("}", "&#125;")
    template = Template("{{ safe_body | safe }}")
    return template.render(safe_body=safe)
