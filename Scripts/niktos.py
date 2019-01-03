#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  NIKTOS                                                                       #
#                                                                               #
#  Run nikto against a list of hosts.                                           #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 27-07-2018                                                    #
#                                                                               #
#################################################################################
name = 'NIKTOS'
version = '1.0.0'
tagline = 'Run nikto against a list of hosts.'

#####################
# IMPORTS
##################### 
import argparse
import os
import subprocess
from Modules import helpers

#####################
# FUNCTIONS
##################### 
def main():
    # Print messages
    helpers.print_script_message(name, version, tagline)

    helpers.print_task_positive('Hold tight...')

    subprocess.run(['mkdir', 'nikto'])

    # Process hostnames
    # Read the file
    with open(os.getcwd() + '/' + args.targets, newline=None) as file:
        for line in file:
            # Strip newlines
            target = line.rstrip('\n')

            # Capture nikto output
            output_nikto = subprocess.check_output(['nikto', '-host', target], universal_newlines=True)

            # Write the nikto output to file
            target = target.replace('.','-')
            nikto_outfile = open('nikto/' + target + '.txt', 'w')
            nikto_outfile.write(str(output_nikto))
            nikto_outfile.close()

#####################
# ARGUMENT PARSING
#####################
# Set up command line argument parsing
parser = argparse.ArgumentParser(description='A simple python scrupt which runs nikto against a list of hosts.')
parser.add_argument('targets', help="A file containing a list of hostname/IP:port")
# Parse the supplied arguments
args = parser.parse_args()

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print (__name__)
