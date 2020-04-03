#!/usr/bin/env python

import ipaddr


def merge_ranges(ranges):
    range_data = [[ipaddr.IPNetwork(r).numhosts, ipaddr.IPNetwork(r)] for r in ranges]
    ranges = [r[1] for r in sorted(range_data)[::-1]]
    unique_ranges = [str(r) for r in sort_ranges(ranges)]

    return unique_ranges


def sort_ranges(ranges):
    if len(ranges) == 1:
        return ranges

    good_ranges = []
    if not ranges:
        return []
    current_range = ranges.pop(0)

    for r in ranges:
        if not current_range.overlaps(r):
            good_ranges.append(r)

    unique_ranges = sort_ranges(good_ranges)
    unique_ranges.append(current_range)

    return unique_ranges
