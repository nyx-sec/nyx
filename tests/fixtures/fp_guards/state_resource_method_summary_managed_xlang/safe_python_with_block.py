"""Resource opens inside Python `with` blocks must not propagate an
Acquire effect onto callers' receivers.

Pre-fix: `build_resource_method_summaries` summarised every method body
containing an `open(...)` callee as Acquire, regardless of whether the
handle was managed by a `with` block (released before return) or bound
to a class field (genuine receiver state).  Callers of `obj.method()`
were then marked OPEN forever, producing the airflow `subject=self` FP
cluster (58 findings).

Post-fix: nodes flagged `managed_resource = true` (Python `with`, Java
try-with-resources, Ruby File.open block) are excluded from the summary
table.
"""


class JWKS:
    """Mimics airflow's tokens.JWKS shape."""

    def __init__(self, url):
        self.url = url

    def _fetch_local_jwks(self):
        try:
            with open(self.url) as jwks_file:
                content = jwks_file.read()
            return content
        except Exception:
            return None


class BundleVersionLockReader:
    """Mimics airflow's BundleUsageTrackingManager._remove_stale_bundle."""

    @staticmethod
    def remove_stale(info):
        try:
            with open(info, "a") as f:
                f.write("x")
        except OSError:
            pass


def use_jwks():
    j = JWKS("/tmp/x")
    j._fetch_local_jwks()


def use_bundle_reader(info):
    r = BundleVersionLockReader()
    r.remove_stale(info)
