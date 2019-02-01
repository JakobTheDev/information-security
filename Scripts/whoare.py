#!/usr/bin/env python3.6
#################################################################################
#                                                                               #
#  WHOARE                                                                       #
#                                                                               #
#  A simple python script which lets you do information gathering on a list of  #
#  hostnames.                                                                   #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.1                                                               #
#  Last modified: 01-02-2019                                                    #
#                                                                               #
#################################################################################
name = 'WHOARE'
version = '1.0.1'
tagline = 'Gathering passive information for a list of hostnames.'

#####################
# IMPORTS
##################### 
import argparse
import os
import re
import subprocess
import sys
import tldextract
import time

from Modules import helpers

#####################
# FUNCTIONS
#####################
def main():
    # Print messages
    helpers.print_script_message(name, version, tagline)
    helpers.print_task_positive('Hold tight...')

    # Check that targets have been supplied
    if (not args.host and not args.list):
        sys.exit('You must supply a target or list of targets. See help (-h) for more details.')

    # Disable all scanning if flags have been supplied
    if (args.theharvester or args.whois or args.dns):
        args.all = False

    # Process hostnames into domains / subdomains etc
    process_hostnames()

    # Run scans based on supplied flags
    if (args.all or args.whois):
        scan_whois()

    if (args.all or args.theharvester):
        scan_the_harvester()

    if(args.all or args.dns):
        scan_dns()


def process_hostnames():
    # If a single target was supplied, create a hostnames file
    if (args.host):
        # Save the hostname
        hostname_filename = 'hostnames.txt'
        hostsfile = open(hostname_filename, 'w')
        hostsfile.write(args.host)
        hostsfile.close()
        # Store the filename
        args.list = hostname_filename

    # Open file streams to write to
    domainsfile = open('domains.txt', 'w')

    # Process hostnames
    # Read the file
    with open(os.getcwd() + '/' + args.list, newline=None) as file:
        for line in file:
            # Strip newlines
            hostname = line.rstrip('\n')

            # If it's not an IP address, hope it's a valid host name. Grab the domain.
            if (not helpers.is_valid_ip(hostname)):
                # Extract the hostname into a tuple
                extract = tldextract.extract(hostname)

                # Write domain names to file
                domainsfile.write('.'.join(extract[1:]) + '\n')

    domainsfile.close()        


def scan_dns():
    helpers.print_heading('Beginning DNS scanning...')

    # Create directories
    subprocess.run(['mkdir', 'dns'])
    subprocess.run(['mkdir', 'dns/nslookup'])
    subprocess.run(['mkdir', 'dns/dnsrecon'])

    hostname_ip_outfile = open('dns/hostname-ip-map.txt', 'w')

    # Do hostname based scanning
    with open(os.getcwd() + '/' + args.list, newline=None) as file:
        for line in file:
            # Strip newlines
            hostname = line.rstrip('\n')

            # NSLOOKUP
            # Capture nslookup output
            try:
                output_nslookup = subprocess.check_output(['nslookup', hostname], universal_newlines=True)
            except subprocess.CalledProcessError:
                continue

            # Retrieve the IP address
            IP = re.search('Address: (.*)', output_nslookup).group(1)

            # Write the nslookup output to file
            filename = hostname.replace('.','-')
            nslookup_outfile = open('dns/nslookup/nslookup-' + filename + '.txt', 'w')
            nslookup_outfile.write(str(output_nslookup))
            nslookup_outfile.close()

            # Write the hostname - IP mappings to file
            hostname_ip_outfile.write(str(hostname) + '\t\t' + IP + '\n')

    # Do domain name based scanning
    with open(os.getcwd() + '/domains.txt', newline=None) as file:
        for line in file:
            # Strip newlines
            domain = line.rstrip('\n')

            # DNSRECON
            # Capture the dnsrecon output
            output_dnsrecon = subprocess.check_output(['dnsrecon', '-a', '-z', '-d', domain], universal_newlines=True)

            # Write the output to file
            domain = domain.replace('.','-')
            outfile = open('dns/dnsrecon/dnsrecon-' + domain + '.txt', 'w')
            outfile.write(str(output_dnsrecon))
            outfile.close()

    hostname_ip_outfile.close()


def scan_the_harvester():
        helpers.print_heading('Beginning theharvester Scanning...')

        # Create a new directory for output files
        subprocess.run(['mkdir', 'theharvester'])

        # Read the file
        with open(os.getcwd() + '/domains.txt', newline=None) as file:
            for line in file:
                # Strip newlines
                domain = line.rstrip('\n')

                # Capture the whois output
                output = subprocess.check_output(['theharvester', '-b', 'all', '-h', '-v', '-d', domain], universal_newlines=True)

                # Write the output to file
                domain = domain.replace('.','-')
                outfile = open('theharvester/theharvester-' + domain + '.txt', 'w')
                outfile.write(str(output))
                outfile.close()


def scan_whois():
        helpers.print_heading('Beginning whois Scanning...')

        # Create a new directory for output files
        subprocess.run(['mkdir', 'whois'])

        # Read the file
        with open(os.getcwd() + '/domains.txt', newline=None) as file:
            for line in file:
                # Strip newlines
                domain = line.rstrip('\n')

                # Capture the whois output
                output = subprocess.check_output(['whois', '-h', 'whois.iana.org', '-H', domain], universal_newlines=True)

                # Write the output to file
                domain = domain.replace('.','-')
                outfile = open('whois/whois-' + domain + '.txt', 'w')
                outfile.write(str(output))
                outfile.close()

#####################
# ARGUMENT PARSING
#####################
# Set up command line argument parsing
parser = argparse.ArgumentParser(description='A simple python Script which lets you do passive information gathering on a list of hosts')
# Targets
target_group = parser.add_argument_group("Targets")
target_group.add_argument('-H', '--host', help='A single target hostname.')
target_group.add_argument('-L', '--list', help='A file containing a list of hostnames or IP addresses, one per line.')
# Scan types
scan_group = parser.add_argument_group("Scan Types")
scan_group.add_argument('-a', '--all', action='store_true', default=True, help='Run all scans (Default. Supply scan flags to enable specific scans.).')
scan_group.add_argument('-d', '--dns', action='store_true', help='Enable DNS scanning.')
scan_group.add_argument('-t', '--theharvester', action='store_true', help='Enable theharvester scanning.')
scan_group.add_argument('-w', '--whois', action='store_true', help='Enable WhoIS scanning.')
# Parse the supplied arguments
args = parser.parse_args()


#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print(__name__)
