import os
import tempfile
import unittest

from utils.common import extract_targets_from_csv, parse_target


class TargetParsingTests(unittest.TestCase):
    def test_parse_target_accepts_ip_port(self):
        targets = parse_target("192.168.1.1:8081, 10.0.0.5:9000")
        self.assertEqual(targets, [
            ("192.168.1.1", 8081, True),
            ("10.0.0.5", 9000, True),
        ])

    def test_extract_targets_from_csv_reads_host_column(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".csv",
            newline="",
            delete=False,
        ) as csv_file:
            csv_file.write("host,ip,port\n")
            csv_file.write("1.1.1.1:8081,1.1.1.1,8081\n")
            csv_file.write("2.2.2.2:9090,2.2.2.2,9090\n")
            csv_path = csv_file.name

        try:
            self.assertEqual(
                extract_targets_from_csv(csv_path),
                ["1.1.1.1:8081", "2.2.2.2:9090"],
            )
        finally:
            os.unlink(csv_path)

    def test_extract_targets_from_csv_uses_ip_port_when_host_is_not_ip(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".csv",
            newline="",
            delete=False,
        ) as csv_file:
            csv_file.write("host,ip,port\n")
            csv_file.write("ckg48-1.3322.org:8989,222.181.10.4,8989\n")
            csv_file.write("5.5.5.5:8080,5.5.5.5,8080\n")
            csv_path = csv_file.name

        try:
            self.assertEqual(
                extract_targets_from_csv(csv_path),
                ["222.181.10.4:8989", "5.5.5.5:8080"],
            )
        finally:
            os.unlink(csv_path)


if __name__ == "__main__":
    unittest.main()
