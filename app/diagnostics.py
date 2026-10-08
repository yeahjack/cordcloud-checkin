"""Value-free metadata for one explicitly requested login diagnostic.

HTML names are untrusted too: only known protocol names may be logged.
Unknown names and duplicate names are represented by counts.
"""
import json
from collections import Counter
from html.parser import HTMLParser


FORM_FIELDS = frozenset({
    'email', 'Email', 'passwd', 'Password', 'csrf_token', 'device_fingerprint',
    'remember', 'remember_me', 'altcha', 'code', 'token', 'method', 'trust_device',
})
CHALLENGE_FIELDS = frozenset({'algorithm', 'challenge', 'salt', 'signature', 'maxnumber'})
ALGORITHMS = frozenset({'SHA-256', 'SHA-384', 'SHA-512'})


def field_summary(fields, allowed=FORM_FIELDS):
    names = list(fields)
    return {
        'known_fields': sorted(set(names) & allowed),
        'unknown_field_count': sum(name not in allowed for name in names),
    }


class FormSummary(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.login_form = False
        self.widgets = 0
        self.names = []
        self.widget_name = 'absent'
        self.widget_attributes = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms += 1
            self.login_form |= attrs.get('id') == 'login-form'
        elif tag == 'input' and attrs.get('name'):
            self.names.append(attrs['name'])
        elif tag == 'altcha-widget':
            self.widgets += 1
            self.widget_attributes.update(set(attrs) & {'challengeurl', 'challenge', 'challengejson', 'name'})
            name = attrs.get('name')
            self.widget_name = 'default' if name is None else ('altcha' if name == 'altcha' else 'other')

    def metadata(self):
        counts = Counter(self.names)
        return {
            'form_count': self.forms,
            'login_form_present': self.login_form,
            'widget_count': self.widgets,
            'widget_name': self.widget_name,
            'widget_protocol_attributes': sorted(self.widget_attributes),
            'csrf_input_count': counts['csrf_token'],
            'duplicate_known_fields': sorted(name for name, count in counts.items() if count > 1 and name in FORM_FIELDS),
            'unknown_duplicate_count': sum(count > 1 and name not in FORM_FIELDS for name, count in counts.items()),
            **field_summary(self.names),
        }


def describe_form(html):
    parser = FormSummary()
    parser.feed(html)
    return parser.metadata()


def describe_challenge(challenge):
    algorithm = challenge.get('algorithm', 'SHA-256')
    return {
        **field_summary(challenge, CHALLENGE_FIELDS),
        'algorithm': algorithm if isinstance(algorithm, str) and algorithm in ALGORITHMS else 'other',
        'required_strings_present': all(isinstance(challenge.get(key), str) and bool(challenge[key])
                                        for key in ('salt', 'challenge', 'signature')),
        'maxnumber_is_integer': type(challenge.get('maxnumber', 1000000)) is int,
    }


def content_type_category(response):
    value = str(response.headers.get('Content-Type', '')).split(';', 1)[0].strip().lower()
    if value in {'application/json', 'text/json'}:
        return 'json'
    if value in {'text/html', 'application/xhtml+xml'}:
        return 'html'
    return 'other' if value else 'missing'


def emit(logger, stage, **metadata):
    # Callers supply fixed stage/metadata keys and sanitized metadata above.
    logger('[diagnostic] ' + json.dumps({'stage': stage, **metadata}, sort_keys=True, ensure_ascii=True))
