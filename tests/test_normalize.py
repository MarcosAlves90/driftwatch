from driftwatch.normalize import normalize_sql


def test_normalize_sql_removes_comments_and_collapses_whitespace():
    assert normalize_sql(" SELECT  1 /* ignored */ -- trailing\n FROM dbo.Users ") == "select 1 from dbo.users"


def test_normalize_sql_preserves_none():
    assert normalize_sql(None) is None


def test_normalize_sql_preserves_literal_case_and_comment_markers():
    assert normalize_sql("SELECT 'HELLO -- not a comment' /* comment */ FROM t") == "select 'HELLO -- not a comment' from t"


def test_normalize_sql_preserves_escaped_quotes_in_literals():
    assert normalize_sql("SELECT 'O''Reilly'") == "select 'O''Reilly'"
