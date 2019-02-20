import os
import codecs


def read_file(path, encoding='iso-8859-1'):
    try:
        with open(path, encoding=encoding) as f:
            data = f.read()
        return data
    except UnicodeDecodeError:
        raise