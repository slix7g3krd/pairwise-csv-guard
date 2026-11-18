from security.csv_guard import (
    escape_cell,
    is_formula,
    sanitize_row,
    sanitize_header,
    safe_filename
)


def test_equals():
    assert escape_cell('=cmd') == "'=cmd"

def test_plus():
    assert is_formula('+1') is True

def test_minus():
    assert is_formula('-1') is True

def test_at():
    assert is_formula('@x') is True

def test_tab():
    assert is_formula('\t=1') is True

def test_cr():
    assert is_formula('\r=1') is True

def test_quote():
    assert escape_cell('"=1"') == "'\"=1\"'"

def test_bom():
    assert is_formula('\ufeff=1') is True

def test_delimiter():
    assert escape_cell('a,b') == '"a,b"'

def test_header():
    assert sanitize_header('=x') == "'=x"

def test_filename():
    assert safe_filename('a\r\n.csv') == 'a.csv'

def test_encoding():
    assert sanitize_row(['=1'])[0].startswith("'")

def test_newline():
    assert '\n' not in sanitize_row(['a\nb'])[0]

def test_safe():
    assert escape_cell('hello') == 'hello'

def test_empty():
    assert sanitize_row([]) == []
