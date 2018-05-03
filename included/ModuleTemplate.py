#!/usr/bin/python
import argparse

class ModuleTemplate(object):
    """
    Master template for a module. Actual modules should just override this

    """
    name = "Template"
    db = None

    def __init__(self, db=None):

        pass


    def set_options(self):

        self.options = argparse.ArgumentParser(prog=self.name)
        self.options.add_argument('-db', "--database", help="Save results to database")
        self.options.add_argument('--db_backend', help="Database module (sqlite default)", default="db_sqlite")
        self.options.add_argument('-b', '--binary', help="Path to the binary")
        


    def run(self, args):
        '''
        Execute the module, receives argparse arguments.
        '''
        pass





