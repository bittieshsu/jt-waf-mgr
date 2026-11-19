"""Which site an access log line belongs to (0.5.12: nginx's shared access.log.38.gz was listed as a site)."""
import gzip
import os
import tempfile
import time
import unittest

from jtwafmgr import evidence

LINE = '203.0.113.7 - - [20/Nov/2026:04:00:00 +0800] "GET /assets/config.json HTTP/1.1" 404 10 "-" "curl/8"\n'


class TestLogSite(unittest.TestCase):
    def test_names(self):
        for name, site in (('access.log', '(default)'), ('access.log.38.gz', '(default)'), ('access.log.1', '(default)'),
                           ('Cloud.example.com.access.log.3.gz', 'cloud.example.com'), ('a.example.com.access.log', 'a.example.com'),
                           ('b.example.com.combined.log.2', 'b.example.com')):
            self.assertEqual(evidence.log_site('/var/log/nginx/' + name), site, name)

    def test_lines_of_a_rotated_shared_log(self):
        with tempfile.TemporaryDirectory() as d:
            with gzip.open(os.path.join(d, 'access.log.38.gz'), 'wt') as fh:
                fh.write(LINE)
            with open(os.path.join(d, 'shop.example.com.access.log'), 'w') as fh:
                fh.write(LINE)
            logs = evidence.AccessLogs({'evidence': {'access_logs': [os.path.join(d, '*')]}})
            self.assertEqual(sorted(x['host'] for x in logs.lines(time.time() + 60)), ['(default)', 'shop.example.com'])


if __name__ == '__main__':
    unittest.main()
