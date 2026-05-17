import json
import unittest
from unittest import mock

from modules import ai_analyzer
from modules.ai_analyzer import AIConfig


class AIConfigTests(unittest.TestCase):
    def test_save_does_not_persist_api_key_when_not_remembered(self):
        opener = mock.mock_open()
        with mock.patch.object(ai_analyzer, "CONFIG_FILE", "ai.json"):
            with mock.patch("builtins.open", opener):
                cfg = AIConfig(api_key="secret-value", remember_api_key=False)
                cfg.save()

        written = "".join(call.args[0] for call in opener().write.call_args_list)
        data = json.loads(written)
        self.assertEqual(data["api_key"], "")
        self.assertFalse(data["remember_api_key"])

    def test_save_persists_api_key_when_remembered(self):
        opener = mock.mock_open()
        with mock.patch.object(ai_analyzer, "CONFIG_FILE", "ai.json"):
            with mock.patch("builtins.open", opener):
                cfg = AIConfig(api_key="secret-value", remember_api_key=True)
                cfg.save()

        written = "".join(call.args[0] for call in opener().write.call_args_list)
        data = json.loads(written)
        self.assertEqual(data["api_key"], "secret-value")
        self.assertTrue(data["remember_api_key"])


if __name__ == "__main__":
    unittest.main()
