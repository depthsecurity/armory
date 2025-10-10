#!/usr/bin/env python
import os
import sys
import tempfile
import subprocess
from django.core.management.base import BaseCommand, CommandError
from armory2.armory_cmd import list_modules, list_reports, load_module
import pdb
import re

class Command(BaseCommand):
    help = "Load all modules and reports, check their requirements, and consolidate into one list"

    def add_arguments(self, parser):
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help="Don't install, just print the discovered requirements"
        )
        parser.add_argument(
            '--pip-args',
            help='Additional arguments to pass to pip install command',
            default=''
        )
        parser.add_argument(
            '--manual-install', '-m', help='Manually install a library into environment'
        )

    def handle(self, *args, **options):
        self.stdout.write("Loading all modules and reports...")
        
        if options['manual_install']:
            self.stdout.write("Manually installing library...")
            self.manual_install(options['manual_install'])
            return
        
        # Get all modules and reports
        modules = list_modules(silent=True)
        reports = list_reports(silent=True)
        
        all_requirements = set()
        
        
        all_modules = modules | reports
        # Process modules
        self.stdout.write(f"Processing {len(modules)} modules...")
        for module_name, module_path in all_modules.items():
            
            try:
                module_path = os.path.join(module_path, module_name) + ".py"
                
                data = open(module_path, 'r').read()
                
                # I know this is really hackish, but importing the modules fails due to the missing libraries.

                requirements = data.split("requirements = ")[1].split("]")[0] + ']' if 'requirements = ' in data else ""

                if requirements:
                    all_requirements.update(eval(requirements))
    
            except Exception as e:
                self.stdout.write(f"  Error loading {module_name}: {e}")
        

    

        self.stdout.write(f"\nSummary:")
        self.stdout.write(f"  Total unique requirements: {len(all_requirements)}")
        
        # Display discovered requirements
        if all_requirements:
            self.stdout.write("\nDiscovered requirements:")
            for req in sorted(all_requirements):
                self.stdout.write(f"  - {req}")
        

        
        # Install requirements if requested
        
        if (not options['dry_run']) and all_requirements:
            self.install_requirements(all_requirements, options['pip_args'])
            
    def install_requirements(self, requirements, pip_args):
        """Install requirements using pip from a temporary file"""
        if not requirements:
            self.stdout.write("No requirements to install.")
            return
            
        # Create a temporary file for requirements
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
            for req in sorted(requirements):
                tmp_file.write(f"{req}\n")
            tmp_file_path = tmp_file.name
        
        try:
            self.stdout.write(f"\nInstalling requirements from temporary file: {tmp_file_path}")
            self.stdout.write("Requirements to install:")
            for req in sorted(requirements):
                self.stdout.write(f"  - {req}")
            
            # Build pip command
            pip_cmd = [sys.executable, '-m', 'pip', 'install', '-r', tmp_file_path]
            if pip_args:
                # Split pip_args and add to command
                pip_cmd.extend(pip_args.split())
            
            self.stdout.write(f"\nRunning command: {' '.join(pip_cmd)}")
            
            # Run pip install
            result = subprocess.run(pip_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.stdout.write("✅ Successfully installed all requirements!")
                if result.stdout:
                    self.stdout.write("Pip output:")
                    self.stdout.write(result.stdout)
            else:
                self.stdout.write("❌ Failed to install some requirements.")
                if result.stderr:
                    self.stdout.write("Error output:")
                    self.stdout.write(result.stderr)
                if result.stdout:
                    self.stdout.write("Standard output:")
                    self.stdout.write(result.stdout)
                    
        except Exception as e:
            self.stdout.write(f"❌ Error running pip install: {e}")
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_file_path)
                self.stdout.write(f"Cleaned up temporary file: {tmp_file_path}")
            except Exception as e:
                self.stdout.write(f"Warning: Could not delete temporary file {tmp_file_path}: {e}")
        
    def generate_output(self, all_requirements, module_requirements, report_requirements, format_type):
        """Generate output in the specified format"""
        
        if format_type == 'json':
            import json
            data = {
                'all_requirements': sorted(list(all_requirements)),
                'module_requirements': module_requirements,
                'report_requirements': report_requirements
            }
            return json.dumps(data, indent=2)
        
        elif format_type == 'requirements':
            # Generate requirements.txt format
            output = []
            for req in sorted(all_requirements):
                output.append(req)
            return '\n'.join(output)
        
        else:  # list format (default)
            output = []
            output.append("ALL REQUIREMENTS:")
            output.append("-" * 20)
            for req in sorted(all_requirements):
                output.append(f"  {req}")
            
            output.append("\nMODULE REQUIREMENTS:")
            output.append("-" * 20)
            for module_name, requirements in sorted(module_requirements.items()):
                if requirements:
                    output.append(f"  {module_name}:")
                    for req in requirements:
                        output.append(f"    - {req}")
                else:
                    output.append(f"  {module_name}: (no requirements)")
            
            output.append("\nREPORT REQUIREMENTS:")
            output.append("-" * 20)
            for report_name, requirements in sorted(report_requirements.items()):
                if requirements:
                    output.append(f"  {report_name}:")
                    for req in requirements:
                        output.append(f"    - {req}")
                else:
                    output.append(f"  {report_name}: (no requirements)")
            
            return '\n'.join(output)

    def manual_install(self, library):
        self.stdout.write(f"Manually installing library: {library}")
        subprocess.run([sys.executable, '-m', 'pip', 'install', library])
        self.stdout.write(f"Successfully installed {library}")
