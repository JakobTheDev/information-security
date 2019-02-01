#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  SCAN                                                                         #
#                                                                               #
#  Scan a single host beginning with simple, light weight scanning followed by  #
#  increasingly thorough and targeted scanning.                                 #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.1                                                               #
#  Last modified: 01-02-2019                                                    #
#                                                                               #
#################################################################################
name = 'SCAN'
version = '1.0.1'
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
    scan_ssl()
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
                print(hostname)

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
