"""Synthetic positive/negative corpus for conservative configuration diagnostics."""

import pytest

from secret_sentinel.unsafe_config import CONFIG_RULE_IDS, iter_config_matches


@pytest.mark.parametrize(
    "path,line,kind",
    [
        (".env", "DEBUG=true", "debug-enabled"),
        ("settings.env", 'export FLASK_DEBUG="1" # development', "debug-enabled"),
        ("settings.ini", "DJANGO_DEBUG: TRUE", "debug-enabled"),
        ("settings.toml", "DEBUG = true", "debug-enabled"),
        ("settings.yaml", "DEBUG: true", "debug-enabled"),
        ("settings.yml", "PYTHONHTTPSVERIFY: 0", "tls-verification-disabled"),
        ("settings.cfg", "NODE_TLS_REJECT_UNAUTHORIZED=0", "tls-verification-disabled"),
        ("settings.json", '  "DEBUG": true,', "debug-enabled"),
        ("settings.json", '{"PYTHONHTTPSVERIFY": "0"}', "tls-verification-disabled"),
        ("settings.py", "DEBUG = True", "debug-enabled"),
        ("settings.py", "FLASK_DEBUG = 1", "debug-enabled"),
        ("settings.py", "DJANGO_DEBUG: bool = True", "debug-enabled"),
        ("settings.py", "app.run(debug=True)", "debug-enabled"),
        (
            "client.py",
            'requests.get("https://example.invalid", verify=False)',
            "tls-verification-disabled",
        ),
        (
            "client.py",
            'requests.request("GET", "https://example.invalid", verify=False)',
            "tls-verification-disabled",
        ),
        ("client.py", "ssl._create_unverified_context()", "tls-verification-disabled"),
        ("settings.py", "ALLOWED_HOSTS = ['*', 'localhost']", "wildcard-allowed-hosts"),
        ("settings.py", "ALLOWED_HOSTS = ('*',)", "wildcard-allowed-hosts"),
    ],
)
def test_known_unsafe_syntax(path, line, kind):
    matches = list(iter_config_matches(line, path))
    assert len(matches) == 1
    assert matches[0].rule_id == "config-" + kind
    assert matches[0].rule_id in CONFIG_RULE_IDS
    assert matches[0].column >= 1
    assert matches[0].confidence == "medium"


@pytest.mark.parametrize(
    "path,line",
    [
        ("readme.md", "DEBUG=true"),
        ("notes.txt", "NODE_TLS_REJECT_UNAUTHORIZED=0"),
        ("settings.js", "DEBUG=true"),
        ("settings.env", "# DEBUG=true"),
        ("settings.yaml", "# DEBUG: true"),
        ("settings.env", "MY_DEBUG=true"),
        ("settings.env", "debug=true"),
        ("settings.env", "DEBUG=false"),
        ("settings.env", "DEBUG=0"),
        ("settings.env", "DEBUG=${DEBUG}"),
        ("settings.env", "DEBUG=1notreally"),
        ("settings.env", "prefix DEBUG=true"),
        ("settings.env", 'TEXT="DEBUG=true"'),
        ("settings.env", "VERIFY=false"),
        ("settings.env", "NODE_TLS_REJECT_UNAUTHORIZED=1"),
        ("settings.json", '"description": "DEBUG=true"'),
        ("settings.json", '"DEBUG": false'),
        ("settings.py", "# DEBUG = True"),
        ("settings.py", 'text = "DEBUG = True"'),
        ("settings.py", '"requests.get(url, verify=False)"'),
        ("settings.py", "DEBUG = bool(environment)"),
        ("settings.py", "DEBUG = 'True'"),
        ("settings.py", "app.run(debug=False)"),
        ("settings.py", "other.run(debug=True)"),
        ("settings.py", "requests.get(url, verify=True)"),
        ("settings.py", "client.get(url, verify=False)"),
        ("settings.py", "requests.get(url, verify=0)"),
        ("settings.py", "ssl.create_default_context()"),
        ("settings.py", "ALLOWED_HOSTS = ['localhost']"),
        ("settings.py", "ALLOWED_HOSTS = [wildcard]"),
        ("settings.py", "ALLOWED_HOSTS = '*'"),
        ("settings.py", "DEBUG = True +"),
    ],
)
def test_safe_unsupported_and_documentation_syntax(path, line):
    assert list(iter_config_matches(line, path)) == []


def test_evidence_never_contains_adjacent_secret_or_url():
    secret = "ghp_1234567890abcdefghijklmnop"
    line = f'requests.get("https://user:{secret}@example.invalid", verify=False)'
    match = next(iter_config_matches(line, "client.py"))
    assert match.evidence == "requests.verify=false"
    assert match.identity == match.evidence
    assert secret not in str(match)
    assert "example.invalid" not in str(match)
    env = next(iter_config_matches("DEBUG=true # " + secret, "settings.env"))
    assert env.evidence == "DEBUG=true"
    assert secret not in str(env)


def test_multiple_calls_and_indentation_have_exact_positions():
    line = '  text="é"; requests.get(url, verify=False); app.run(debug=True)'
    matches = list(iter_config_matches(line, "client.py"))
    assert [match.column for match in matches] == [
        line.index("requests") + 1,
        line.index("app.run") + 1,
    ]


def test_bounded_and_malformed_inputs_are_safe():
    assert list(iter_config_matches("DEBUG=True" + " " * 20000, "settings.py")) == []
    assert list(iter_config_matches("[" * 1000, "settings.py")) == []
    assert list(iter_config_matches("DEBUG=True\x00", "settings.py")) == []


@pytest.mark.parametrize(
    "path,line",
    [
        ("settings.yaml", "DEBUG=true"),
        ("settings.toml", "DEBUG: true"),
        ("settings.toml", "export DEBUG=true"),
        ("settings.toml", "DEBUG=TRUE"),
        ("settings.json", '"DEBUG": TRUE'),
        ("settings.env", "DEBUG: true"),
    ],
)
def test_assignment_grammar_matches_file_format(path, line):
    assert list(iter_config_matches(line, path)) == []


def test_multiline_python_strings_are_identified_without_executing():
    from secret_sentinel.unsafe_config import python_multiline_string_ranges

    text = '"""Documentation\nDEBUG = True\n"""\nDEBUG = True\n'
    assert python_multiline_string_ranges(text) == [(1, 3)]


def test_unterminated_python_string_blocks_remainder():
    from secret_sentinel.unsafe_config import python_multiline_string_ranges

    text = 'DEBUG = True\n"""Documentation\nDEBUG = True\n'
    blocked = python_multiline_string_ranges(text)
    assert blocked == [(2, 4)]


@pytest.mark.parametrize("path", [".env.local", ".env.production", "nested/.env.test"])
def test_env_variants_are_recognized(path):
    assert (
        next(iter_config_matches("DEBUG=true", path)).rule_id == "config-debug-enabled"
    )


def test_newline_heavy_docstring_uses_one_interval():
    from secret_sentinel.unsafe_config import python_multiline_string_ranges

    text = '"""' + "\n" * 10000 + '"""'
    assert python_multiline_string_ranges(text) == [(1, 10001)]
