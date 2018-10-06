#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  RESOLVE                                                                      #
#                                                                               #
#  Resolve a list of hostnames in to IP adddresses.                             #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.1                                                               #
#  Last modified: 06-10-2018                                                    #
#                                                                               #
#################################################################################
name = 'RESOLVE'
version = '1.0.1'
tagline = 'Resolve a list of hostnames in to IP adddresses.'

#####################
# IMPORTS
##################### 
import argparse
import os
import subprocess
from Modules import helpers
from pathlib import Path

#####################
# FUNCTIONS
##################### 
def main():
    # Print messages
    helpers.print_script_message(name, version, tagline)
    helpers.print_task_positive('Hold tight...')

    # Output file name
    if(args.output):
        output_name = args.output
    else:
        output_name = 'resolved.txt'

    # Open output file
    output_file = open(output_name, 'w')

    # read the list of hostnames, line by line.
    with open(os.getcwd() + '/' + args.hostnames, newline=None) as file:
        for line in file:
            # Strip newlines
            hostname = line.rstrip('\n')

            # Do a host lookup
            try:
                output_host = subprocess.check_output(['host', hostname], universal_newlines=True)
            except subprocess.CalledProcessError as e:
                output_host = e.output
            
            if(len(output_host.split()) >= 3): 
                ip = output_host.split()[len(output_host.split())-1]
            else:
                ip = 'NOT_FOUND'

            if(not helpers.is_valid_ip(ip)):  
                ip = 'UNDEFINED'

            output_file.write(hostname + ':' + ip + '\n')

    # Close the output file
    output_file.close()

    # Finished
    print('[+] Resolved IPs written to ' + output_name)


#####################
# ARGUMENT PARSING
#####################
# Set up command line argument parsing
parser = argparse.ArgumentParser(description='A simple python script which resolves a list of hostnames into IPs.')
parser.add_argument('hostnames', help="A file containing a list of hostnames")
parser.add_argument('-o', '--output', help="Output file name")
# Parse the supplied arguments
args = parser.parse_args()

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print (__name__)
