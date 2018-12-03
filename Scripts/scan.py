#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  SCAN                                                                         #
#                                                                               #
#  Scan a single host beginning with simple, light weight scanning followed by  #
#  increasingly thorough and targeted scanning.                                 #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 16-05-2018                                                    #
#                                                                               #
#  TODO: Everything                                                             #
#                                                                               #
#################################################################################
name = 'SCAN'
version = '1.0.0'
tagline = 'Perform initial scanning against a target.'

#####################
# IMPORTS
##################### 
import argparse
import os
import subprocess
import sys
from Modules import helpers

#####################
# GLOBALS
##################### 
devnull = open(os.devnull, 'w')

#####################
# FUNCTIONS
##################### 
def main():
    # Print messages
    helpers.print_script_message(name, version, tagline)
    helpers.print_task_positive('Hold tight...')

    # Test the IP address
    if(not helpers.is_valid_ip(args.ip)):
        print('Please use a valid IP address.')
        sys.exit('Exiting.')

    # Orchestrate scanning components
    nmap_fast()
    scan_web()
    nmap_all_ports()

def nmap_fast():
    # Prepare for nmap scanning
    # Print heading
    helpers.print_heading('Performing nmap scanning')
    # Declare global variable
    global output_nmap_fast
    # Create nmap directory
    helpers.mkdir('nmap')

    # Do fast scan
    helpers.print_task_positive('Fast nmap scanning')
    output_nmap_fast = subprocess.check_output(['nmap', '-sV', '-O', args.ip, '-oA', 'nmap/nmap-fast'], universal_newlines=True)
    print()

def scan_web():
    # Prepare for web scanning
    # Print heading
    helpers.print_heading('Performing web scanning')
    # Test for common web ports
    web_ports = helpers.get_web_ports(output_nmap_fast)

    # If there are open web ports, scan them
    if(not len(web_ports)):
        helpers.print_task_negative('No open web ports...')
    else:
        # Create nikto directory
        helpers.mkdir('nikto')
        # Make a directory to store results
        for port in web_ports:
            scan_web_port(port)

    # Finised web scanning
    helpers.print_task_positive('Finished scanning web ports')
    print()
    
def scan_web_port(port):
    # Prepare for web scanning
    helpers.print_task_positive('Web scanning port ' + str(port))

    ## Nikto scanning
    helpers.print_subtask_positive('Nikto scanning port ' + str(port))
    subprocess.run(['nikto', '-host', args.ip + ':' + str(port), '-o', 'nikto/nikto-' + str(port) + '.txt'], stdout=devnull, stderr=devnull)

    ## nmap scanning
    helpers.print_subtask_positive('Nmap scanning port ' + str(port))
    subprocess.run(['nmap', '-A', '--script=http-title,http-headers,http-methods,http-enum', '-p' + str(port), args.ip, '-oA', 'nmap/nmap-web-' + str(port)], stdout=devnull, stderr=devnull)

def nmap_all_ports():
# Prepare for nmap scanning
    # Print heading
    helpers.print_heading('More nmap scanning')
    # Declare global variable
    global output_nmap_all_ports

    # Do scan over all ports
    helpers.print_subtask_positive('Nmap scanning all ports')
    output_nmap_all_ports = subprocess.check_output(['nmap', '-p-','-sV', '-O', args.ip, '-oA', 'nmap/nmap-allports'], universal_newlines=True)
    
    # Do a service scan over all open ports
    # TODO
    
    print()

#####################
# ARGUMENT PARSING
#####################
# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Scan a single host beginning with simple, light weight scanning followed by increasingly thorough and targeted scanning.')
parser.add_argument('ip', help='The hosts IP address.')
# Parse the supplied arguments
args = parser.parse_args()

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print (__name__)
