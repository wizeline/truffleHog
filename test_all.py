import unittest
import os
import re
from pprint import pprint
from collections import namedtuple
from truffleHog import truffleHog


class TestStringMethods(unittest.TestCase):

    def test_shannon(self):
        BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        HEX_CHARS = "1234567890abcdefABCDEF"
        random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        random_stringHex = "b3A0a1FDfe86dcCE945B72"
        self.assertGreater(truffleHog.shannon_entropy(random_stringB64, BASE64_CHARS), 4.5)
        self.assertGreater(truffleHog.shannon_entropy(random_stringHex, HEX_CHARS), 3)

    def test_cloning(self):
        project_path = truffleHog.clone_git_repo("https://github.com/dxa4481/truffleHog.git")
        license_file = os.path.join(project_path, "LICENSE")
        self.assertTrue(os.path.isfile(license_file))

    def test_unicode_expection(self):
        try:
            truffleHog.find_strings("https://github.com/dxa4481/tst.git")
        except UnicodeEncodeError:
            self.fail("Unicode print error")

    def test_is_line_disabled(self):
        self.assertTrue(truffleHog.is_line_disabled("some text ... # not-a-secret"))
        self.assertTrue(not truffleHog.is_line_disabled("some text ... "))

    def test_path_included(self):
        Blob = namedtuple('Blob', ['b_path', 'a_path'])
        blob = Blob(b_path="", a_path="")
        self.assertTrue(truffleHog.path_included(
            blob, include_patterns=None, exclude_patterns=None))

        # False
        blob = Blob(b_path="file_a", a_path=None)
        self.assertFalse(truffleHog.path_included(
            blob, include_patterns=None, exclude_patterns=[re.compile("file_a")]))

        blob = Blob(b_path="file_b", a_path=None)
        self.assertFalse(truffleHog.path_included(
            blob, include_patterns=[re.compile("file_a")], exclude_patterns=None))

        # True
        blob = Blob(b_path="file_b", a_path=None)
        self.assertTrue(truffleHog.path_included(
            blob, include_patterns=None, exclude_patterns=[re.compile("file_a")]))

        blob = Blob(b_path="file_a", a_path=None)
        self.assertTrue(truffleHog.path_included(
            blob, include_patterns=[re.compile("file_a")], exclude_patterns=None))

    def test_find_base64_shannon_entropy(self):
        printable_diff = """
        hello
        ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva
        bye
        """
        word = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"

        strings_found, printable_diff = truffleHog.find_base64_shannon_entropy(printable_diff, word)
        self.assertEqual(
            strings_found,
            ['ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva'])
        self.assertEqual(printable_diff, (
            '\n'
            '        hello\n'
            '        '
            '\x1b[93mZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva\x1b[0m\n'
            '        bye\n'
            '        '))

    def test_find_hex_shannon_entropy(self):
        printable_diff = """
        hello
        b3A0a1FDfe86dcCE945B72
        bye
        """
        word = "b3A0a1FDfe86dcCE945B72"
        strings_found, printable_diff = truffleHog.find_hex_shannon_entropy(printable_diff, word)
        self.assertEqual(strings_found, ['b3A0a1FDfe86dcCE945B72'])
        self.assertEqual(printable_diff, (
            '\n'
            '        hello\n'
            '        \x1b[93mb3A0a1FDfe86dcCE945B72\x1b[0m\n'
            '        bye\n'
            '        '))



if __name__ == '__main__':
    unittest.main()
