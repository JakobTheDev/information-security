#!/usr/bin/env python3.6
#################################################################################
#                                                                               #
#  WHOARE                                                                       #
#                                                                               #
#  A simple python script which lets you do information gathering on a list of  #
#  hostnames.                                                                   #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 05-03-2018                                                    #
#                                                                               #
#################################################################################

#####################
# IMPORTS
##################### 
import argparse
import os
import ptvsd
import re
import subprocess
import sys
import tldextract
import time

from Modules import helpers

#####################
# GLOBALS
#####################
DEBUGGING_ENABLED = False
DEBUGGING_PORT = 3000
DEUGGING_IP = '127.0.0.1'
DEBUGGING_PASSWORD = ''

#####################
# FUNCTIONS
#####################
def main():
    if(DEBUGGING_ENABLED):
        # Allow other computers to attach to ptvsd at this IP address and port, using the secret
        ptvsd.enable_attach(DEBUGGING_PASSWORD, address = (DEUGGING_IP, DEBUGGING_PORT))

        # Pause the program until a remote debugger is attached
        ptvsd.wait_for_attach()

     # Check that targets have been supplied
    if (not args.host and not args.list):
        sys.exit('You must supply a target or list of targets. See help (-h) for more details.')

    # Disable all scanning if flags have been supplied
    if (args.ssl or args.theharvester or args.whois or args.dns):
        args.all = False

    # Process hostnames into domains / subdomains etc
    process_hostnames()

    # Run scans based on supplied flags
    if (args.all or args.ssl):
        scan_ssl()

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


# TODO Move to Poke
def scan_ssl():
        helpers.print_heading('Beginning SSL Scanning...')
        # Create  directories for output files
        subprocess.run(['mkdir', 'ssl'])
        subprocess.run(['mkdir', 'ssl/scan-output'])
        subprocess.run(['mkdir', 'ssl/vulnerabilities'])

        # Read the file
        with open(os.getcwd() + '/' + args.list, newline=None) as file:
            for line in file:
                # Strip newlines
                hostname = line.rstrip('\n')

                # Capture the sslscan output
                output_sslscan = subprocess.check_output(['sslscan', hostname], universal_newlines=True)

                # Remove ANSI encoding so we can search
                output_sslscan_clean = helpers.remove_ansi(output_sslscan)

                # Process the SSLScan output
                # SSL / TLS versions
                # SSLv2
                if (output_sslscan_clean.find('SSLv2') != -1):
                    helpers.print_task_positive('SSLv2')
                    vuln_file = open('ssl/vulnerabilities/tls-sslv2-0.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # SSLv3
                if (output_sslscan_clean.find('SSLv3') != -1):
                    helpers.print_task_positive('SSLv3')
                    vuln_file = open('ssl/vulnerabilities/tls-sslv3-0.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # TLSV1.0
                if (output_sslscan_clean.find('TLSv1.0') != -1):
                    helpers.print_task_positive('TLSv1.0')
                    vuln_file = open('ssl/vulnerabilities/tls-tlsv1-0.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # TLS Fallback SCSV
                if (output_sslscan_clean.find('Server does not support TLS Fallback SCSV') != -1):
                    helpers.print_task_positive('TLS Fallback SCSV')
                    vuln_file = open('ssl/vulnerabilities/tls-fallback-scsv.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # TLS CRIME
                if (output_sslscan_clean.find('Compression enabled (CRIME)') != -1):
                    helpers.print_task_positive('Compression enabled (CRIME)')
                    vuln_file = open('ssl/vulnerabilities/tls-compression-crime.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Certificate issues
                # Expired certificate
                if (helpers.remove_control_characters(output_sslscan).find('Not valid after:  [31m') != -1):
                    helpers.print_task_positive('Expired certificate')
                    vuln_file = open('ssl/vulnerabilities/certificate-expired.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Wildcard certificate
                if (output_sslscan_clean.find('Subject:  *') != -1):
                    helpers.print_task_positive('Wildcard certificate')
                    vuln_file = open('ssl/vulnerabilities/certificate-wildcard.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Weak certificate signature
                if (output_sslscan_clean.find('sha1WithRSA') != -1):
                    helpers.print_task_positive('Weak certificate signature')
                    vuln_file = open('ssl/vulnerabilities/certificate-weak-signature.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Cipher suites
                # Export ciphers
                if (output_sslscan_clean.find('EXP-') != -1):
                    helpers.print_task_positive('Weak cipher - Export cipher')
                    vuln_file = open('ssl/vulnerabilities/weak-cipher-export.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # RC4
                if (output_sslscan_clean.find('RC4') != -1):
                    helpers.print_task_positive('Weak cipher - RC4')
                    vuln_file = open('ssl/vulnerabilities/weak-cipher-rc4.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # DES-CBC(3)-SHA
                if (output_sslscan_clean.find('DES-CBC') != -1):
                    helpers.print_task_positive('Weak cipher - DES-CBC')
                    vuln_file = open('ssl/vulnerabilities/weak-cipher-des-cbc.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Weak diffie hellman
                if (output_sslscan_clean.find('DHE 1024 bits') != -1):
                    helpers.print_task_positive('Weak cipher - DHE 1024 bits')
                    vuln_file = open('ssl/vulnerabilities/weak-cipher-dhe-1024.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()
                    

                # Capture the sslyze output
                output_sslyze = subprocess.check_output(['sslyze', '--regular', '--hsts', hostname], universal_newlines=True)

                # Process the sslyze output (Only what is missed by SSLScan)
                # Client initiated renegotiation
                if (output_sslyze.find('VULNERABLE - Server honors client-initiated renegotiations') != -1):
                    helpers.print_task_positive('Server honors client-initiated renegotiations')
                    vuln_file = open('ssl/vulnerabilities/tls-client-initiated-renegotiations.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Missing HSTS header
                if (output_sslyze.find('NOT SUPPORTED - Server did not send an HSTS header.') != -1):
                    helpers.print_task_positive('HSTS Unsupported')
                    vuln_file = open('ssl/vulnerabilities/tls-hsts-unsupported.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Self-signed certificate
                if (output_sslyze.find('FAILED - Certificate is NOT Trusted: self signed certificate') != -1):
                    helpers.print_task_positive('FAILED - Certificate is NOT Trusted: self signed certificate')
                    vuln_file = open('ssl/vulnerabilities/tls-self-signed-certificate.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Mismatched certificate
                if (output_sslyze.find('FAILED - Certificate does NOT') != -1):
                    helpers.print_task_positive('FAILED - Certificate does NOT match')
                    vuln_file = open('ssl/vulnerabilities/tls-mismatched-certificate.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Untrusted certificate
                if (output_sslyze.find('FAILED - Certificate is NOT Trusted') != -1):
                    helpers.print_task_positive('FAILED - Certificate is NOT Trusted')
                    vuln_file = open('ssl/vulnerabilities/tls-untrusted-certificate.txt', 'a')
                    vuln_file.write(str(hostname) + '\n')
                    vuln_file.close()

                # Write the output to file
                hostname = hostname.replace('.','-')
                outfile = open('ssl/scan-output/ssl-' + hostname + '.txt', 'w')
                outfile.write(str(output_sslscan))
                outfile.write(str(output_sslyze))
                outfile.close()


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
scan_group.add_argument('-s', '--ssl', action='store_true', help='Enable SSL scanning.')
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
