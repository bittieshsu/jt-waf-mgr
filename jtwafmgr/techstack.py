"""Technologies: the languages, frameworks and libraries under the software of this site, and which ones a CrowdSec Hub
rule is about. A flaw in a framework or library (React2Shell, Spring4Shell, PHP2Shell, Log4Shell, a template engine...)
reaches every application built on it, not one product: such a rule is "cross-application" and relates to every site
whose software runs on that technology, and may be applied to all sites at once.

Plain data; no network. The application table is what is publicly known about each product's stack; a person adds
whatever else runs (a technology can be entered in the software list like any product)."""
import re

# technology -> the broader ones it implies
IMPLIES = {
    'Spring': ('Java',), 'Struts': ('Java',), 'Log4j': ('Java',), 'FreeMarker': ('Java',), 'Tomcat': ('Java',),
    'Jetty': ('Java',), 'Quarkus': ('Java',), 'Jackson': ('Java',),
    'Laravel': ('PHP',), 'Symfony': ('PHP',), 'PHPUnit': ('PHP',),
    'Django': ('Python',), 'Flask': ('Python',),
    'React': ('Node.js',), 'Next.js': ('React', 'Node.js'), 'Express': ('Node.js',),
    'Rails': ('Ruby',), 'ASP.NET': ('.NET',), 'Telerik': ('.NET',),
}

# libraries bundled by nearly every application of their language: a flaw in one relates to all of them
BUNDLED = {'Log4j', 'Jackson'}

# application (every word of the key in the product's name) -> technologies it is built on
APP_STACK = {
    'zimbra': ('Java', 'Jetty'), 'keycloak': ('Java', 'Quarkus'), 'jenkins': ('Java', 'Jetty'),
    'confluence': ('Java', 'Tomcat', 'Spring'), 'jira': ('Java', 'Tomcat', 'Spring'), 'bitbucket': ('Java', 'Spring'),
    'xwiki': ('Java',), 'metabase': ('Java',), 'elasticsearch': ('Java',), 'solr': ('Java',), 'liferay': ('Java', 'Tomcat'),
    'ofbiz': ('Java',), 'guacamole': ('Java', 'Tomcat'), 'nexus': ('Java', 'Jetty'), 'sonarqube': ('Java',),
    'jitsi': ('Java',), 'openfire': ('Java', 'Jetty'), 'tomcat': ('Tomcat',), 'jetty': ('Jetty',),
    'nextcloud': ('PHP',), 'owncloud': ('PHP',), 'librenms': ('PHP', 'Laravel'), 'observium': ('PHP',),
    'z push': ('PHP',), 'roundcube': ('PHP',), 'wordpress': ('PHP',), 'drupal': ('PHP', 'Symfony'), 'joomla': ('PHP',),
    'phpmyadmin': ('PHP',), 'moodle': ('PHP',), 'mediawiki': ('PHP',), 'magento': ('PHP',), 'adobe commerce': ('PHP',),
    'zabbix': ('PHP',), 'glpi': ('PHP', 'Symfony'), 'cacti': ('PHP',), 'dolibarr': ('PHP',), 'suitecrm': ('PHP',),
    'mautic': ('PHP', 'Symfony'), 'snipe': ('PHP', 'Laravel'), 'bookstack': ('PHP', 'Laravel'), 'firefly': ('PHP', 'Laravel'),
    'matomo': ('PHP',), 'dokuwiki': ('PHP',), 'phpbb': ('PHP', 'Symfony'), 'prestashop': ('PHP', 'Symfony'),
    'opencart': ('PHP',), 'grav': ('PHP', 'Symfony'), 'typo3': ('PHP', 'Symfony'), 'kanboard': ('PHP',),
    'freepbx': ('PHP',), 'vbulletin': ('PHP',), 'cpanel': ('Perl',), 'zoneminder': ('PHP',), 'pfsense': ('PHP',),
    'odoo': ('Python',), 'zulip': ('Python', 'Django'), 'netbox': ('Python', 'Django'), 'paperless': ('Python', 'Django'),
    'seafile': ('Python', 'Django'), 'superset': ('Python', 'Flask'), 'airflow': ('Python', 'Flask'),
    'synapse': ('Python',), 'home assistant': ('Python',), 'mlflow': ('Python', 'Flask'), 'langflow': ('Python',),
    'sentry': ('Python', 'Django'), 'weblate': ('Python', 'Django'), 'mailman': ('Python', 'Django'),
    'gitlab': ('Ruby', 'Rails'), 'discourse': ('Ruby', 'Rails'), 'redmine': ('Ruby', 'Rails'), 'mastodon': ('Ruby', 'Rails'),
    'openproject': ('Ruby', 'Rails'), 'ghost': ('Node.js', 'Express'), 'strapi': ('Node.js',), 'n8n': ('Node.js',),
    'uptime kuma': ('Node.js',), 'rocket chat': ('Node.js',), 'kibana': ('Node.js', 'React'), 'wiki js': ('Node.js',),
    'outline': ('Node.js', 'React'), 'flowise': ('Node.js', 'React'), 'onlyoffice': ('Node.js',),
    'grafana': ('Go', 'React'), 'gitea': ('Go',), 'mattermost': ('Go', 'React'), 'exchange': ('.NET', 'ASP.NET'),
    'sharepoint': ('.NET', 'ASP.NET'),
}

# a technology named in a rule's product, label or name
RULE_TECH = [
    (r'\bspring(?:4shell|boot|framework)?\b', ('Spring',)), (r'\bstruts2?\b', ('Struts',)),
    (r'\blog4(?:j|shell)\b|\bjndi\b', ('Log4j',)), (r'\bfreemarker\b', ('FreeMarker',)), (r'\btomcat\b', ('Tomcat',)),
    (r'\bjetty\b', ('Jetty',)), (r'\bjackson\b|\bfastjson\b|\bxstream\b', ('Jackson',)), (r'\bjava\b', ('Java',)),
    (r'\blaravel\b', ('Laravel',)), (r'\bsymfony\b', ('Symfony',)), (r'\bphpunit\b', ('PHPUnit',)),
    (r'\bphp(?:2shell|[ -]?cgi|[ -]?fpm)?\b', ('PHP',)),
    (r'\bdjango\b', ('Django',)), (r'\bflask\b|\bwerkzeug\b|\bjinja2?\b', ('Flask',)), (r'\bpython\b', ('Python',)),
    (r'\bnext\.?js\b', ('Next.js',)), (r'\breact(?:2shell)?\b', ('React',)),
    (r'\bnode(?:\.?js|2shell)\b|\bexpress\b', ('Node.js',)), (r'\bjava2shell\b', ('Java',)),
    (r'\brails\b|\bruby\b', ('Rails',)), (r'\basp\.?net\b|\b\.net\b', ('ASP.NET',)), (r'\btelerik\b', ('Telerik',)),
]
_RULE_TECH = [(re.compile(rx, re.I), t) for rx, t in RULE_TECH]

# a product that IS a framework, library, language or engine (not one application): the flaw reaches every application
# built on it
CROSS_PRODUCT = re.compile(
    r'^(?:apache\s+)?(?:[a-z0-9.]{2,12}2shell|log4shell|spring\w*|struts2?|log4j\w*|freemarker|tomcat|jetty|jackson|fastjson|xstream|java|'
    r'laravel(?:\s+(?:ignition|debug\s+mode))?|symfony(?:\s+profiler)?|phpunit|php(?:2shell)?(?:[\s-]+(?:cgi|fpm))?|django|flask|werkzeug|jinja2?|python|'
    r'next\.?js|react\w*|node\.?js|express|ruby\s+on\s+rails|rails|ruby|asp\.?net|telerik(?:\s+ui)?|brotli|openssl|'
    r'libxml2?|zlib|lua|pcre2?|imagemagick|ghostscript|nginx|apache(?:\s+http\s+server)?|http/2)$', re.I)

# no product: a weakness of any site (a file left readable, a debug page left open, a request shape)
GENERIC_PRODUCT = re.compile(r'^(?:environment\s+file|git\s+configuration|missing\s+user-agent\s+header|'
                             r'server-side\s+template\s+injection|directory\s+listing|backup\s+files?)$', re.I)

# hub rules that are no protection to apply (examples, base configuration, exclusions for the CRS plugins)
NOT_A_RULE = re.compile(r'^crowdsecurity/(?:appsec-generic-test|base-config|crs|crs-exclusion-plugin-.*)$')


def expand(techs):
    """Every technology with the broader ones it implies (Next.js -> React, Node.js), in a stable order."""
    out, todo = [], list(techs)
    while todo:
        t = todo.pop(0)
        if t not in out:
            out.append(t)
            todo += list(IMPLIES.get(t, ()))
    return out


def _words(s):
    return re.findall(r'[a-z0-9]+', (s or '').lower())


def app_techs(name):
    """The technologies under a product of the software list (its own name when it is one, e.g. "PHP" entered by a
    person), or []."""
    w = ' '.join(_words(name))
    out = []
    for key, techs in APP_STACK.items():
        if re.search(r'(?:^| )%s(?: |$)' % re.escape(key), w):
            out += techs
    for rx, techs in _RULE_TECH:
        if rx.fullmatch((name or '').strip()):
            out += techs
    return expand(out)


def _about(rule):
    label = rule.get('label') or ''
    return rule.get('product') or (label.split(' - ')[0] if label else '')


def rule_profile(rule):
    """{'scope': 'cross' | 'app' | 'none', 'techs': [...]} for a hub rule. 'cross': not one application -- a framework,
    library, language or engine (its product is one), or a generic rule with no product at all (a .env or .git probe,
    a debug page left open); 'none': not a protection (examples, base configuration, CRS plugin exclusions)."""
    name = rule.get('name') or ''
    if NOT_A_RULE.match(name):
        return {'scope': 'none', 'techs': [], 'match': []}
    about = _about(rule).strip()
    generic = not about or bool(GENERIC_PRODUCT.match(about))
    cross = generic or bool(CROSS_PRODUCT.match(about))
    techs = []
    if cross:
        # the technology the rule is about: its product, not words of the flaw's kind ("PHP Object Injection" in a
        # WordPress plugin is no flaw of PHP)
        for rx, t in _RULE_TECH:
            if rx.search(about):
                techs += t
    direct = list(dict.fromkeys(techs))
    # the sites a rule relates to: through the technologies it names, not the broader ones they imply (a Spring flaw is
    # no flaw of every Java application) -- except libraries that nearly every application of the language bundles
    match = direct + [b for t in direct if t in BUNDLED for b in IMPLIES[t] if b not in direct]
    return {'scope': 'cross' if cross else 'app', 'techs': direct, 'match': match}


def related_by_tech(rule_techs, products):
    """The confirmed software whose stack shares a technology with the rule: [{'name': tech, 'via': [products],
    'sites': [...]}] (most specific technology first: a Spring rule relates through Spring before Java)."""
    if not rule_techs:
        return []
    out = []
    for tech in rule_techs:
        via, sites = [], []
        for p in products:
            if tech in app_techs(p['name']):
                via.append(p['name'])
                sites += [s for s in p['sites'] if s not in sites]
        if via:
            out.append({'name': tech, 'via': via, 'sites': sites})
    return out
