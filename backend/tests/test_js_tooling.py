from __future__ import annotations

from subprocess import CompletedProcess
from unittest.mock import patch

import app.services.transforms.js_tooling as js_tooling


class TestJavaScriptToolingBootstrap:
    def teardown_method(self):
        js_tooling._INSTALL_ATTEMPTS.clear()

    def test_javascript_tooling_available_bootstraps_missing_parser_tooling(self):
        js_tooling._INSTALL_ATTEMPTS.clear()
        with patch.object(js_tooling, "_node_executable", return_value="node"), patch.object(
            js_tooling,
            "_tooling_modules_present",
            return_value=False,
        ), patch.object(
            js_tooling,
            "_javascript_tooling_auto_install_enabled",
            return_value=True,
        ), patch.object(
            js_tooling,
            "install_javascript_tooling",
            return_value={"ok": True},
        ) as install:
            assert js_tooling.javascript_tooling_available() is True

        install.assert_called_once_with(require_webcrack=False)

    def test_install_javascript_tooling_honors_offline_cache_arguments(self):
        js_tooling._INSTALL_ATTEMPTS.clear()
        with patch.object(js_tooling, "_node_executable", return_value="node"), patch.object(
            js_tooling,
            "_npm_executable",
            return_value="npm",
        ), patch.object(
            js_tooling,
            "_tooling_modules_present",
            side_effect=[False, False, True],
        ), patch(
            "app.services.transforms.js_tooling.subprocess.run",
            return_value=CompletedProcess(["npm"], 0, "", ""),
        ) as run:
            result = js_tooling.install_javascript_tooling(
                require_webcrack=True,
                force=True,
                offline=True,
                cache_dir="/tmp/unweaver-npm-cache",
            )

        assert result["ok"] is True
        command = run.call_args.args[0]
        assert command[:2] == ["npm", "ci"]
        assert "--offline" in command
        assert "--cache" in command
        assert "/tmp/unweaver-npm-cache" in command
