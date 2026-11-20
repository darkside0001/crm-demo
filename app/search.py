def like_pattern(term: str) -> str:
    """Build a LIKE pattern that matches `term` literally.

    The value is still passed as a bound parameter; escaping % and _ only
    stops a user from turning a search box into an expensive wildcard scan.
    """
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
