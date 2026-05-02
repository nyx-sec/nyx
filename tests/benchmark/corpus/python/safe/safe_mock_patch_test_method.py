# py-auth-realrepo-010: pytest test method decorated with
# `@mock.patch("...")` collides with Flask's `<app>.<verb>` route
# decorator shape (bare_method_name("mock.patch") == "patch", which the
# parse_flask_route_decorator matched as HTTP PATCH).  The collision
# attached the test method as a Flask route handler, flipped its
# `unit.kind` to RouteHandler, made it pass
# `unit_has_user_input_evidence` unconditionally, and flooded pytest
# test suites with `missing_ownership_check` findings.
#
# Distilled from airflow
# `providers/google/tests/unit/google/cloud/hooks/test_dlp.py` (47 FPs
# in this single file pre-fix).  Fix:
# `parse_flask_route_decorator` short-circuits when the callee text
# matches a known test-framework decorator vocabulary
# (`mock.patch`, `unittest.mock.patch`, `monkeypatch.setattr`,
# `pytest.mark.parametrize`, …).
#
# This fixture verifies pytest test methods don't fire ownership-check
# findings, even when they call ORM-shaped APIs with id-suffixed
# constants (the canonical pytest fixture-data pattern).
from unittest import mock
from unittest.mock import PropertyMock

ORGANIZATION_ID = "fake-org-id-123"
PROJECT_ID = "fake-proj-id-456"
DLP_JOB_ID = "fake-job-id-789"


class TestCloudDLPHook:
    @mock.patch(
        "module.GoogleBaseHook.project_id",
        new_callable=PropertyMock,
        return_value=None,
    )
    @mock.patch("module.CloudDLPHook.get_conn")
    def test_create_deidentify_template_with_org_id(self, get_conn, mock_project_id):
        get_conn.return_value.create_deidentify_template.return_value = "API_RESPONSE"
        result = self.hook.create_deidentify_template(organization_id=ORGANIZATION_ID)
        return result

    @mock.patch("module.CloudDLPHook.get_conn")
    def test_create_dlp_job(self, get_conn):
        result = self.hook.create_dlp_job(project_id=PROJECT_ID)
        return result

    @mock.patch.object(SomeClass, "method")
    def test_with_object_patch(self, mock_method):
        self.hook.cancel_dlp_job(dlp_job_id=DLP_JOB_ID)


class SomeClass:
    pass
