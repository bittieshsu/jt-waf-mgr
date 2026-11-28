"""API: application protection sets (protsets.py) -- what applies to which site, and proposing a set's rules as one
change (the usual checks, sandbox and a person's approval)."""
from .. import protsets, scoreblock
from ..changes import ChangeError
from .server import ApiError, json_response

V = '/api/v1'


def protsets_list(app, req):
    return json_response(200, {'sets': protsets.status(app), 'adopted': app.workflow.managed.adopted()})


def protsets_propose(app, req):
    b = req.body()
    actor, via = (req.user['username'], 'user') if req.user is not None else (req.token['name'], 'api')
    role = req.user['role'] if req.user is not None else None
    if via == 'user' and role == 'viewer':
        raise ApiError(403, 'forbidden')
    owner = req.token['created_by'] if via == 'api' else None
    try:
        cid = protsets.propose(app, str(b.get('set') or ''), b.get('host'), b.get('rules'), actor, via, role=role,
                               owner=owner)
    except protsets.ProtsetError as e:
        raise ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)
    except ChangeError as e:
        raise ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)
    r = app.workflow.get(cid)
    return json_response(202, {'change_id': cid, 'direction': r['direction'], 'state': r['state']})


def scoreblock_status(app, req):
    return json_response(200, scoreblock.status(app))


def scoreblock_propose(app, req):
    """0.5.48: propose the rule that makes the CRS score refuse outside requests (people only: it changes what the
    WAF refuses on every site, and for a DSM site it brings an exclusion)."""
    if req.user is None or req.user['role'] not in ('admin', 'approver', 'operator'):
        raise ApiError(403, 'forbidden')
    try:
        cid = scoreblock.propose(app, req.user['username'], 'user', role=req.user['role'])
    except scoreblock.ScoreBlockError as e:
        raise ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)
    except ChangeError as e:
        raise ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)
    r = app.workflow.get(cid)
    return json_response(202, {'change_id': cid, 'direction': r['direction'], 'state': r['state']})


def register(router):
    R = router.add
    R('GET', V + '/protsets', protsets_list, ('role', 'viewer', 'rules:read'))
    R('POST', V + '/protsets/propose', protsets_propose, ('role', 'viewer', 'changes:propose'))
    R('GET', V + '/scoreblock', scoreblock_status, ('role', 'viewer', 'rules:read'))
    R('POST', V + '/scoreblock/propose', scoreblock_propose, ('role', 'operator', None))
