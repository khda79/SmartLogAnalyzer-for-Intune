import unittest

from modules.anonymizer import anonymize_text


class AnonymizerTests(unittest.TestCase):
    def test_anonymize_text_redacts_common_identifiers(self):
        text = (
            "UPN=user@example.com\n"
            "TenantId: 11111111-2222-3333-4444-555555555555\n"
            "DeviceId=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
            "Correlation bbbbbbbb-cccc-dddd-eeee-ffffffffffff\n"
            "IP 192.168.1.20\n"
            "Path C:\\Users\\Khaled\\AppData\\Local"
        )

        redacted = anonymize_text(text)

        self.assertNotIn("user@example.com", redacted)
        self.assertNotIn("11111111-2222-3333-4444-555555555555", redacted)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", redacted)
        self.assertNotIn("bbbbbbbb-cccc-dddd-eeee-ffffffffffff", redacted)
        self.assertNotIn("192.168.1.20", redacted)
        self.assertNotIn("Khaled", redacted)
        self.assertIn("<REDACTED>", redacted)
        self.assertIn("<GUID>", redacted)
        self.assertIn("<IPV4>", redacted)


if __name__ == "__main__":
    unittest.main()
