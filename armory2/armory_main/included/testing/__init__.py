"""
Armory's in-tree test framework.

* ``discovery`` -- finds every module, report, and webapp (core and custom) and
  the ``Tests`` class each one may declare.
* ``fixtures``  -- builds the sample dataset every test class starts from.
* ``smoke``     -- the built-in checks that run against every tool, whether or
  not it ships tests of its own.
* ``runner``    -- creates the throwaway database, runs the suite, prints the
  summary. This is what ``armory -t`` calls.

Test authors import from ``armory2.armory_main.included.TestTemplate``, not
from here.
"""
