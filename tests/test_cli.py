"""
Unit tests for Crypta Feature 1 — CLI Foundation and Design System.
"""

import io
import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from crypta import __version__
from crypta.utils.constants import VERSION, APPLICATION_NAME
from crypta.cli.interface import main
from crypta.utils.terminal import set_color_enabled


class TestCryptaCLI(unittest.TestCase):
    """Test suite for Crypta CLI commands, routing, and styling."""

    def setUp(self):
        set_color_enabled(False)  # Disable ANSI colors during unit testing

    def test_package_imports_and_version(self):
        """Verify package version constant and module exports."""
        self.assertEqual(__version__, "1.0.0")
        self.assertEqual(VERSION, "1.0.0")
        self.assertEqual(APPLICATION_NAME, "Crypta")

    def test_main_help_output(self):
        """Verify main CLI --help output."""
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            exit_code = main(["--help"])
            self.assertEqual(exit_code, 0)
            output = captured_output.getvalue()
            self.assertIn("Crypta", output)
            self.assertIn("Usage:", output)
            self.assertIn("Commands:", output)
            self.assertIn("hide", output)
            self.assertIn("extract", output)
            self.assertIn("capacity", output)
            self.assertIn("info", output)
            self.assertIn("analyze", output)
            self.assertIn("report", output)
        finally:
            sys.stdout = sys.__stdout__

    def test_version_flag(self):
        """Verify --version flag output."""
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            exit_code = main(["--version"])
            self.assertEqual(exit_code, 0)
            output = captured_output.getvalue()
            self.assertIn("Crypta 1.0.0", output)
        finally:
            sys.stdout = sys.__stdout__

    @patch("getpass.getpass", return_value="SecretTestPass123!")
    def test_subcommand_routing(self, mock_getpass):
        """Verify all six subcommands route to handlers cleanly."""
        # Create a temporary PNG carrier image for testing routing handlers
        temp_dir = tempfile.mkdtemp()
        try:
            test_png = Path(temp_dir) / "test_carrier.png"
            img = Image.new("RGB", (100, 100))
            img.save(test_png, format="PNG")

            test_secret = Path(temp_dir) / "secret.txt"
            test_secret.write_bytes(b"SECRET_TEST_PAYLOAD")

            stego_out = Path(temp_dir) / "stego_out.png"

            subcommand_args = {
                "hide": [str(test_png), str(test_secret), str(stego_out)],
                "extract": [str(stego_out)],
                "capacity": [str(test_png)],
                "info": [str(test_png)],
                "analyze": [str(test_png)],
                "report": [str(test_png)],
            }

            for cmd, args in subcommand_args.items():
                captured_output = io.StringIO()
                sys.stdout = captured_output
                try:
                    exit_code = main([cmd] + args)
                    self.assertEqual(exit_code, 0, f"Command '{cmd}' failed with code {exit_code}")
                    output = captured_output.getvalue()
                    self.assertTrue(
                        "initialized" in output
                        or "validated" in output
                        or "extracted" in output
                        or "embedded" in output
                        or "recovered" in output
                        or "detected" in output,
                        f"Unexpected output for {cmd}: {output}",
                    )
                finally:
                    sys.stdout = sys.__stdout__
        finally:
            shutil.rmtree(temp_dir)

    def test_subcommand_help_screens(self):
        """Verify command-specific --help screens for all six subcommands."""
        subcommands = ["hide", "extract", "capacity", "info", "analyze", "report"]
        for cmd in subcommands:
            captured_output = io.StringIO()
            sys.stdout = captured_output
            try:
                exit_code = main([cmd, "--help"])
                self.assertEqual(exit_code, 0, f"Command '{cmd} --help' failed with code {exit_code}")
                output = captured_output.getvalue()
                self.assertIn(cmd.upper(), output)
                self.assertIn("Usage:", output)
            finally:
                sys.stdout = sys.__stdout__

    def test_invalid_command_error(self):
        """Verify invalid CLI syntax handled gracefully without crashing."""
        captured_stderr = io.StringIO()
        sys.stderr = captured_stderr
        try:
            with self.assertRaises(SystemExit) as cm:
                main(["invalid_cmd_xyz"])
            self.assertEqual(cm.exception.code, 2)
            stderr_output = captured_stderr.getvalue()
            self.assertIn("Invalid command syntax", stderr_output)
        finally:
            sys.stderr = sys.__stderr__

    def test_interactive_shell_session(self):
        """Verify interactive shell session accepts input and exits cleanly."""
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            with patch("builtins.input", side_effect=["version", "exit"]):
                exit_code = main([])
                self.assertEqual(exit_code, 0)
                output = captured_output.getvalue()
                self.assertIn("Interactive Crypta shell active", output)
                self.assertIn("Crypta 1.0.0", output)
                self.assertIn("Exiting Crypta shell", output)
        finally:
            sys.stdout = sys.__stdout__


if __name__ == "__main__":
    unittest.main()
