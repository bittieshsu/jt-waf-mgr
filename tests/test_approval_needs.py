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
        self.assertEqual(self.needs(row(op='nginx', direction='neutral', by='cli:jason')), {'totp': True, 'note_min': 10})
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
