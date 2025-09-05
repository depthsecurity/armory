# This is the roadmap for Armory v3

## The tool itself

- Get the original tool working again outside of Docker, as an installable pipx package
- Set up a repo on pypy for installation
- Clean out all of the old dependencies
- Create a guided configuration script for setting up a new install
- Add an option for docker build/update that checks if the tool is installed locally and only build the docker image if it is not

## Modules

- Set up an overridable binary search that will check if the tool exists locally, if not checks for docker package, finally errors out
- Set up tags, and assign tags to various tools
- Look into creating a yaml framework for defining new modules, if they are very straightforward (ie a new domain lister, etc).
  - Tough part is handing output consistently

## Reports

- Set up ability to use docker files
- Refine the screenshot tooling
 
## Webapps

- Create a webapp for system and module configuration
- Revamp the host summary to automatically add in objects based on type

## API/AI

- Add in an API and MCP