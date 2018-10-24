#!/usr/bin/python


def run(txt, colsizes, delim="\t"):

    coldata = txt.split(delim)
    res = []

    assert len(coldata) == len(colsizes)

    for i in range(len(coldata)):
        if len(coldata[i]) >= colsizes[i]:
            res.append(coldata[i][: colsizes[i]])
        else:
            res.append(coldata[i] + (" " * (colsizes[i] - len(coldata[i]))))

    return " ".join(res)
