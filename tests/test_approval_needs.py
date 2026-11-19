"""What approving a change takes (changes.approval_needs, 0.4.100): the change page shows the one-time code field from
the same rule approve() follows -- the field once missed the nginx update's, which the server required."""
import json
import unittest

from jtwafmgr.changes import Workflow


def row(op='add', direction='tighten', by='alice', via='user', owner=None, spec=None):
    return {'op': op, 'direction': direction, 'proposed_by': by, 'proposed_via': via, 'proposed_owner': owner,
            'spec': json.dumps(spec or {})}


class TestApprovalNeeds(unittest.TestCase):
    def needs(self, r, user='bob'):
        return Workflow.approval_needs(Workflow.__new__(Workflow), r, user)

    def test_cases(self):
        self.assertEqual(self.needs(row(op='nginx', direction='neutral', by='cli:jason')), {'totp': True, 'note_min': 4})
        self.assertTrue(self.needs(row(op='nginx', direction='neutral', by='bob'))['totp'])       # own: one code covers both
        self.assertEqual(self.needs(row()), {'totp': False, 'note_min': 0})                      # someone else's tightening
        self.assertFalse(self.needs(row(direction='loosen'))['totp'])                            # someone else's loosening
        self.assertTrue(self.needs(row(direction='loosen', by='bob'))['totp'])                   # one's own loosening
        self.assertTrue(self.needs(row(direction='loosen', by='tok', via='api', owner='bob'))['totp'])   # own token's
        self.assertFalse(self.needs(row(direction='tighten', by='bob'))['totp'])
        self.assertTrue(self.needs(row(direction='loosen', spec={'strict': True}))['totp'])      # a whole category off
        self.assertTrue(self.needs(row(direction='loosen', by='analyst'))['totp'])               # the model's loosening
        self.assertFalse(self.needs(row(direction='tighten', by='analyst'))['totp'])


if __name__ == '__main__':
    unittest.main()


class TestApproveSpendsTheCodeOnlyOnce(unittest.TestCase):
    """0.5.0: a short note was refused after the code had been spent; the same code then read "enter a code"."""

    def test_short_note_keeps_the_code(self):
        import time
        from jtwafmgr import auth
        from jtwafmgr.app import App
        from jtwafmgr.changes import ChangeError
        from tests.helpers import TempEnv
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg, start_collector=False)
        app.auth.create_user('boss', 'admin', password='Long-Passw0rd-xyz')
        secret = auth.totp_new_secret()
        app.db.x('UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?', (secret, 'boss'))
        now = time.time()
        cid = app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, proposed_via, created_at, "
                       "updated_at, rule_text, tests) VALUES ('nginx','system','{}','neutral','pending_approval','r','nginxup',"
                       "'user',?,?,'','[]')", (now, now)).lastrowid
        user = app.db.one("SELECT * FROM users WHERE username='boss'")
        code = auth.totp_code(secret, int(time.time() // 30))
        with self.assertRaises(ChangeError) as e:
            app.workflow.approve(cid, user, totp=code, note='go')
        self.assertEqual(e.exception.code, 'note_required')
        self.assertFalse(app.db.one("SELECT totp_last_step FROM users WHERE username='boss'")[0])     # not spent
        # spent once (as by a sign-in a moment ago): "already used", not counted as a wrong code
        app.db.x('UPDATE users SET totp_last_step=? WHERE username=?', (int(time.time() // 30) + 1, 'boss'))
        with self.assertRaises(ChangeError) as e:
            app.workflow.approve(cid, user, totp=code, note='nginx security update')
        self.assertEqual(e.exception.code, 'totp_used')
        self.assertEqual(app.db.one("SELECT COUNT(*) FROM audit WHERE action='auth.step_up_failed'")[0], 0)
