from driftwatch.normalize import normalize_sql


def test_normalize_sql_removes_comments_and_collapses_whitespace():
    assert normalize_sql(" SELECT  1 /* ignored */ -- trailing\n FROM dbo.Users ") == "select 1 from dbo.users"


def test_normalize_sql_preserves_none():
    assert normalize_sql(None) is None
