#!/usr/bin/python

from database.repositories import IPRepository, DomainRepository, PortRepository, UrlRepository
from included.ModuleTemplate import ModuleTemplate
from subprocess import Popen
from included.utilities import which, get_urls
import shlex
import os
import pdb
import tempfile

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Module(ModuleTemplate):
    
    name = "Gowitness"

    def __init__(self, db):
        self.db = db
        self.IPAddress = IPRepository(db, self.name)
        self.Domain = DomainRepository(db, self.name)
        self.Port = PortRepository(db, self.name)
        self.Url = UrlRepository(db, self.name)
        

    def set_options(self):
        super(Module, self).set_options()

        self.options.add_argument('--chrome-path', help="Full path to Chrome executable to use. By default, gowitness will search for Google chrome.")
        self.options.add_argument('--chrome-timeout', help="Timeout for taking screenshot")
        self.options.add_argument('-o', '--output_path', help='Prefix path for storage of screenshots and database (default base_path/gowitness)', default="gowitness")
        self.options.add_argument('-R', '--resolution', help="Screenshot resolution. Default \"1440,900\"")
        self.options.add_argument('-T', '--timeout', help="Timeout for HTTP connection (default 3)")
        self.options.add_argument('-i', '--import_database', help="Import URLs from the database", action="store_true")
        self.options.add_argument('-f', '--import_file', help="Import URLs from file")
        self.options.add_argument('--group_size', help="How many hosts per group (default 250)", type=int, default=300)

    def run(self, args):
        
        if not args.binary:
            self.binary = which.run('gowitness')

        else:
            self.binary = which.run(args.binary)

        if not self.binary:
            print("Gowitness binary not found. Please explicitly provide path with --binary")

        # pdb.set_trace()
        
        elif args.import_file:
            urls = open(args.file).read().split('\n')
            self.process_urls(urls, args)

        elif args.import_database:
            urls = get_urls.run(self.db)

            self.process_urls(urls, args)

    def process_urls(self, urls, args):


        i = 0

        for url_chunk in self.chunks(urls, args.group_size):
            i += 1
            print("Processing group %s" % i)
            
            command_args = " file "

            if args.chrome_path:
                command_args += " --chrome-path %s " % args.chrome_path

            if args.chrome_timeout:
                command_args += " --chrome-timeout %s " % args.chrome_timeout

            if args.resolution:
                command_args += " -R %s " % args.resolution

            if args.timeout:
                command_args += " -T %s " % args.timeout

            if args.output_path[0] == "/":
                self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] +"_%s" % i)
            else:
                self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path+"_%s" % i)

            if not os.path.exists(self.path):
                os.makedirs(self.path)

            _, file_name = tempfile.mkstemp()

            open(file_name, 'w').write('\n'.join(url_chunk))
            

            command_args += " -D %s/gowitness.db -d %s -s %s " % (self.path, self.path, file_name)

            cmd = shlex.split(self.binary + command_args)
            
            print("Executing: %s" % ' '.join(cmd))
            
            
            Popen(cmd, shell=False).wait()
            
            print("Screenshotting done. Generating index.html.")

            command_args = " generate -D %s/gowitness.db -d %s -n %s/report.html" % (self.path, self.path, self.path)

            cmd = shlex.split(self.binary + command_args)
            
            print("Executing: %s" % ' '.join(cmd))
            # pdb.set_trace()
            Popen(cmd, shell=False).wait()


    def chunks(self, chunkable, n):
        """ Yield successive n-sized chunks from l.
        """
        for i in xrange(0, len(chunkable), n):
            yield chunkable[i:i+n]