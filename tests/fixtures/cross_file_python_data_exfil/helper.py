"""Wrapper around requests.post whose two parameters target distinct
gated-sink classes on the inner call: `url` is the SSRF gate's destination
(arg 0); `body` is the DATA_EXFIL gate's payload (json kwarg).  Pass-1 SSA
summary extraction lifts the per-position cap split into
`param_to_gate_filters` so cross-file callers can attribute SSRF vs
DATA_EXFIL per argument.
"""
import requests


def forward(url, body):
    requests.post(url, json=body)
