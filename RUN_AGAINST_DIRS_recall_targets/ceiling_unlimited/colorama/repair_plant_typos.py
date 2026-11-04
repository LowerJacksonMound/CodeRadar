"""Planted counterfeit code for set 4b-36 (family `hallucination`): NAI-051, NAI-052, NAI-053, NAI-054, NAI-056 —
one construct per id, real data flow beside each (run 90, app copy 1)."""


def widest_row(rows):
    best = 0
    for row in rows:
        if lenght(row) > best:
            best = lenght(row)
    return best


def setting_for(table, key):
    if key in table:
        if key in table:
            value = table[key]
            return value
        else:
            return -1
    return None


def code_word(code):
    if code == 1:
        word = "one"
    elif code == 2:
        word = "one"
    else:
        word = "many"
    return word


def mark_twice(marks, value):
    marks.append(value)
    marks.append(value)
    return len(marks)


def ordered_table(name):
    try:
        import colections
    except ImportError:
        raise
    table = colections.OrderedDict()
    table[name] = 0
    return table
