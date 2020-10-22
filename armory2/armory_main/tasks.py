#!/usr/bin/env python3

from django_q.tasks import async_task, result
import subprocess
import shlex

def launch_job(module, args, logfile):
    if type(args) == list:
        args_list = args
    else:
        args_list = shlex.split(args)
    with open(logfile, 'a') as f:
        launcher = subprocess.Popen(['armory2', '-m', module] + args_list, stdout=f, stderr=f)

        launcher.wait()
        


    

