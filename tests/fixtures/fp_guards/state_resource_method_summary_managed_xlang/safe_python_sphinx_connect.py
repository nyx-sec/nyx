"""Sphinx / Flask / MQTT-style event handler `app.connect(event, cb)`
must not be flagged as a DB connection acquire by the generic `connect`
matcher.

Pre-fix: `app.connect("config-inited", _create_init_py)` matched the
ends-with-`.connect` acquire pattern; the static `exclude_acquire`
list only carved out `signal.connect`, `event.connect`, and `.register`,
missing Sphinx's `app.connect` and similar event-handler dispatchers.

Post-fix: `is_event_handler_register_shape` (string-literal first arg
without `scheme://` plus a single-identifier second positional arg)
recognises the canonical handler shape and suppresses the acquire on
`db connection` pairs only.  Real `engine.connect("postgres://...")`
shapes still fire because their first arg carries a `://`.
"""


def setup(app):
    app.connect("config-inited", _on_config_inited)
    app.connect("html-page-context", _on_page_context)
    app.connect("build-finished", _on_build_finished)


def _on_config_inited(app, config):
    pass


def _on_page_context(app, pagename, templatename, context, doctree):
    pass


def _on_build_finished(app, exception):
    pass


class MqttListener:
    def setup(self, client):
        client.connect("device/status/+", self._on_status)

    def _on_status(self, topic, payload):
        pass
