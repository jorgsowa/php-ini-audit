import unittest

from php_ini_audit import values


class ValuesTest(unittest.TestCase):
    def test_bool_follows_zend_ini_parse_bool(self):
        for text in ("1", "On", "yes", "TRUE", "2", " 1 "):
            self.assertTrue(values.to_bool(text), text)
        for text in ("", "0", "Off", "no", "stderr", None, "abc"):
            self.assertFalse(values.to_bool(text), text)

    def test_quantities(self):
        self.assertEqual(values.to_bytes("128M"), 128 * 1024**2)
        self.assertEqual(values.to_bytes("2g"), 2 * 1024**3)
        self.assertEqual(values.to_bytes("-1"), -1)
        self.assertEqual(values.to_bytes("0x10"), 16)
        self.assertIsNone(values.to_bytes("lots"))

    def test_error_reporting_expression(self):
        self.assertEqual(values.eval_error_reporting("E_ALL"), 32767)
        self.assertEqual(values.eval_error_reporting("E_ALL & ~E_DEPRECATED & ~E_STRICT"), 32767 & ~8192 & ~2048)
        self.assertEqual(values.eval_error_reporting("(E_ERROR | E_WARNING)"), 3)
        self.assertEqual(values.eval_error_reporting("0"), 0)
        self.assertIsNone(values.eval_error_reporting("E_BOGUS"))
        self.assertIsNone(values.eval_error_reporting("__import__('os')"))

    def test_list_split(self):
        self.assertEqual(values.split_list("exec, system,,popen  shell_exec"), ["exec", "system", "popen", "shell_exec"])


if __name__ == "__main__":
    unittest.main()
