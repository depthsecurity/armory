
def is_ip(txt):

    valid = '01234567890.'

    res = ""

    for t in txt:
        if t in valid:
            res += t

    return res == txt
    