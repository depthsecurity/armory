import os
import codecs
from .color_display import display_error


def read_file(path, encoding="iso-8859-1", raise_exception=False):
    try:
        with open(path, encoding=encoding) as f:
            data = f.read()
        return data
    except UnicodeDecodeError as exc:
        if raise_exception:
            raise
        else:
            display_error(
                "Unable to open file '{}' with '{}' encoding. Exception which occurred: {}".format(
                    path, encoding, exc
                )
            )
            return "Failed to open Whois file: {} with '{}' encoding.".format(
                path, encoding
            )
