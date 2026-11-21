# Reading an attribute of the cursor does not move the cursor into `desc`.
# Expected: one state-resource-leak, on the cursor.


def rows(connection, sql):
    cursor = connection.cursor()
    cursor.execute(sql)
    desc = cursor.description
    return [dict(zip([c[0] for c in desc], r)) for r in cursor.fetchall()]
