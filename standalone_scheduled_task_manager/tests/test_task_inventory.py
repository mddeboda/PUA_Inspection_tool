import unittest

from task_inventory import ScheduledTaskRecord, parse_scheduled_tasks_csv, validate_hostname


class TaskInventoryTests(unittest.TestCase):
    def test_parses_summary_csv(self):
        output = '"HostName","TaskName","Next Run Time","Status"\n"PC1","\\Example","8/8/2026 1:00:00 AM","Ready"\n'
        records = parse_scheduled_tasks_csv(output, default_hostname="fallback")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].hostname, "PC1")
        self.assertEqual(records[0].task_name, "\\Example")
        self.assertEqual(records[0].status, "Ready")

    def test_microsoft_task_is_protected(self):
        record = ScheduledTaskRecord("PC1", "\\Microsoft\\Windows\\UpdateOrchestrator\\Task")
        self.assertTrue(record.is_microsoft_windows_task)

    def test_search_is_case_insensitive(self):
        record = ScheduledTaskRecord("PC1", "\\Backup", action="PowerShell.exe -File backup.ps1")
        self.assertIn("powershell", record.searchable_text())

    def test_hostname_validation_rejects_command_characters(self):
        with self.assertRaises(ValueError):
            validate_hostname("PC1 & whoami")


if __name__ == "__main__":
    unittest.main()
