from included.ModuleTemplate import ModuleTemplate
from database.repositories import BaseDomainRepository, DomainRepository
from included.utilities import which
import os
import subprocess
import re
from exceptions import IOError
from tld import get_tld

class Module(ModuleTemplate):

	name = "Fierce"

	def __init__(self, db):
		self.db = db
		self.BaseDomain = BaseDomainRepository(db, self.name)
		self.Domain = DomainRepository(db, self.name)

	def set_options(self):
		super(Module, self).set_options()
		self.options.add_argument('-d','--domain', help="Target domain for Fierce")
		self.options.add_argument('-f', '--file', help="Import domains from file")
		self.options.add_argument('-i', '--import_database', help="Import domains from database", action="store_true")
		self.options.add_argument('-o', '--output_path', help="Relative path (to the base directory) to store Fierce output", default="fierceFiles")
		self.options.add_argument('-x', '--fiercefile', help="Fierce output name")
		self.options.add_argument('--threads', help="Number of threads to use", default="10")
		self.options.add_argument('--force', help="Force overwrite", action="store_true")
		self.options.add_argument('--import_file', help="Import Fierce file")


	def run(self, args):
		
		if not args.binary:
			self.binary = which.run('fierce')

		else:
			self.binary = which.run(args.binary)

		if not self.binary:
			print("Fierce binary not found. Please explicitly provide path with --binary")

		if args.output_path[0] == "/":
			self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path[1:] )
		else:
			self.path = os.path.join(self.base_config['PROJECT']['base_path'], args.output_path)

		if not os.path.exists(self.path):
			os.makedirs(self.path)

		if args.domain:
			created, domain = self.BaseDomain.find_or_create(domain=args.domain)
			self.process_domain(domain, args)
			self.BaseDomain.commit()

		elif args.file:
			domains = open(args.file).read().split('\n')
			for d in domains:
				if d:
					created, domain = self.BaseDomain.find_or_create(domain=d)
					self.process_domain(domain, args)
					self.BaseDomain.commit()

		elif args.import_database:
			domains = self.BaseDomain.all(tool=self.name, scope_type="passive")
			for domain in domains:
				self.process_domain(domain, args)				
				domain.set_tool(self.name)
				self.BaseDomain.commit()

		elif args.import_file:
			fiercefile = args.import_file
			self.process_data(fiercefile, args)
			self.BaseDomain.commit()

		else:
			print("You need to supply some options to do something.")	

	def process_domain(self, domain_obj, args):

		domain = domain_obj.domain
		print("Processing %s" % domain)
		if args.fiercefile:
			fiercefile = os.path.join(self.path,args.fiercefile)

		else:
			fiercefile = os.path.join(self.path,domain+".txt")

		if os.path.isfile(fiercefile):
			if not args.force:
				answered = False
				while answered == False:
					rerun = raw_input("Would you like to [r]un Fierce again and overwrite the file, [p]arse the file, or change the file [n]ame? ")
					if rerun.lower() == 'r':
						answered = True
					
					elif rerun.lower() == 'p':
						answered = True
						return fiercefile

					elif rerun.lower() == 'n':
						new = False
						while new == False:
							newFile = raw_input("enter a new file name: ")
							if not os.path.exists(os.path.join(self.path,newFile)):
								fiercefile = os.path.join(path,newFile)
								answered = True
								new = True
							else:
								print "That file exists as well"

		command = self.binary

		if args.threads:
			command += " -threads %s " % args.threads

		command += " -dns {} -file {} ".format(domain, fiercefile)
		
		subprocess.Popen(command, shell=True).wait()

		try:
			self.process_data(fiercefile, args)

		except IOError:
			print("Fierce for %s failed." % domain)
			return None

	def process_data(self, fiercefile, args):
		self.fiercefile = fiercefile
		print "Reading", self.fiercefile
		fierceOutput = ''
		with open(self.fiercefile,'r') as fiercefile:
			for line in fiercefile:
				fierceOutput += line
		
		domains = []		

		if "Now performing" in fierceOutput:
			hosts = re.findall("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\t.*$",fierceOutput,re.MULTILINE)
			if hosts:
				for host in hosts:
					#print host
					domain = host.split("\t")[1].lower().replace("www.","").rstrip(".")
					if domain not in domains:
						domains.append(domain)
					
		elif "Whoah, it worked" in fierceOutput:
			print "Zone transfer found!"
			hosts = re.findall(".*\tA\t\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",fierceOutput,re.MULTILINE)
			if hosts:
				for host in hosts:
					domain = host.split("\t")[0].lower().replace("www.","").rstrip(".")
					if domain not in domains:
						domains.append(domain)
					
		else:
			print "Unable to process {}".format(fiercefile)

		if domains:
			for _domain in domains:
				
				created, domain = self.Domain.find_or_create(domain=_domain)
				
		return 
