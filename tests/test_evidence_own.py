"""0.5.37: jt-waf-mgr's own requests (reading a version, a health check) are not evidence that people use a path:
revproxy2's Synology set failed its evidence check on the program's own GET /webman/info.cgi from 127.0.0.1."""
import unittest

from jtwafmgr import evidence


class TestOwnRequests(unittest.TestCase):
    def test_own(self):
        evidence._lan.v = '192.0.2.10'
        self.assertTrue(evidence._own_request({'ua': 'jt-waf-mgr version check', 'ip': '127.0.0.1'}))
        self.assertTrue(evidence._own_request({'ua': 'jt-waf-mgr-apply health check', 'ip': '::1'}))
        self.assertTrue(evidence._own_request({'ua': 'jt-waf-mgr version check', 'ip': '192.0.2.10'}))
        self.assertFalse(evidence._own_request({'ua': 'jt-waf-mgr version check', 'ip': '203.0.113.9'}))   # someone else
        self.assertFalse(evidence._own_request({'ua': 'Mozilla/5.0', 'ip': '127.0.0.1'}))
        self.assertFalse(evidence._own_request({'ua': 'jt-waf-mgr version check; x', 'ip': '127.0.0.1'}))


if __name__ == '__main__':
    unittest.main()
