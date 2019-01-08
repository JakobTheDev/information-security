#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  NIKTOS                                                                       #
#                                                                               #
#  Run nikto against a list of hosts.                                           #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.1.0                                                               #
#  Last modified: 08-01-2019                                                    #
#                                                                               #
#################################################################################
name = 'NIKTOS'
version = '1.1.0'
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

    # Make output directory
    subprocess.run(['mkdir', 'nikto'])
    subprocess.run(['mkdir', 'nikto/scan-output'])
    subprocess.run(['mkdir', 'nikto/vulnerabilities'])

    # Default web ports
    web_ports = ['80', '443']

    # Process hostnames
    # Read the file
    with open(os.getcwd() + '/' + args.targets, newline=None) as file:
        for line in file:
            # Strip newlines
            target = line.rstrip('\n')

            for port in web_ports:
                # Run scan and capture the output
                helpers.print_task_positive('Beginning scan - Port: ' + port + ' Target: ' + target)

                # Force SSL on port 443
                if (port == '80'):
                    output_nikto = subprocess.check_output(['nikto', '-host', target, '-ask', 'auto'], universal_newlines=True)
                else:
                    output_nikto = subprocess.check_output(['nikto', '-host', target, '-ask', 'auto', '-ssl'], universal_newlines=True)

                # Print the output to terminal, if selected
                if (args.print): 
                    print(output_nikto)

                # Interpret results
                if (args.interpret):
                    interpret(target, port, output_nikto)

                # Write the nikto output to file
                target_dash = target.replace('.','-')
                nikto_outfile = open('nikto/scan-output/' + target_dash + '-' + port + '.txt', 'w')
                nikto_outfile.write(str(output_nikto))
                nikto_outfile.close()

    # Print message if interpret option was selected
    if (args.interpret):
        print("")
        helpers.print_heading("Scans complete")
        helpers.print_task_positive("The output above only includes dumb interpretation of scan results.")
        helpers.print_task_positive("See the full output in nikto/scan-output for the fun stuff :)")

def interpret(target, port, output):
    # Print output
    helpers.print_subtask_positive("Interpreting results...")

    # Return if no results
    if (output.find("0 host(s) tested") != -1):
        return

    # Process the scan output
    # Server header
    if (output.find('Server: No banner retrieved') == -1):
        helpers.print_subtask_negative('Header found: Server')
        vuln_file = open('nikto/vulnerabilities/header-server.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # X-Powered-By header
    if (output.find('Retrieved x-powered-by header:') != -1):
        helpers.print_subtask_negative('Header found: X-Powered-By')
        vuln_file = open('nikto/vulnerabilities/header-x-powered-by.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # X-AspNet-Version header
    if (output.find('Retrieved x-aspnet-version header:') != -1):
        helpers.print_subtask_negative('Header found: X-AspNet-Version')
        vuln_file = open('nikto/vulnerabilities/header-x-powered-by.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # X-Frame-Options header
    if (output.find('The anti-clickjacking X-Frame-Options header is not present.') != -1):
        helpers.print_subtask_negative('Missing header: X-Frame-Options')
        vuln_file = open('nikto/vulnerabilities/missing-header-x-frame-options.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # X-XSS-Protection header
    if (output.find('The X-XSS-Protection header is not defined.') != -1):
        helpers.print_subtask_negative('Missing header: X-XSS-Protection')
        vuln_file = open('nikto/vulnerabilities/missing-header-x-xss-protection.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # X-Content-Type-Options header
    if (output.find('The X-Content-Type-Options header is not set.') != -1):
        helpers.print_subtask_negative('Missing header: X-Content-Type-Options')
        vuln_file = open('nikto/vulnerabilities/missing-header-x-content-type-options.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # Strict-Transport-Security header
    if (output.find('The site uses SSL and the Strict-Transport-Security HTTP header is not defined.') != -1):
        helpers.print_subtask_negative('Missing header: Strict-Transport-Security')
        vuln_file = open('nikto/vulnerabilities/missing-header-strict-transport-security.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # Cookie missing secure attribute
    if (output.find('created without the secure flag') != -1):
        helpers.print_subtask_negative('Cookie missing attribute: Secure')
        vuln_file = open('nikto/vulnerabilities/missing-cookie-attribute-secure.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # Cookie missing secure attribute
    if (output.find('created without the secure flag') != -1):
        helpers.print_subtask_negative('Cookie missing attribute: Secure')
        vuln_file = open('nikto/vulnerabilities/missing-cookie-attribute-secure.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

    # Cookie missing http attribute
    if (output.find('created without the httponly flag') != -1):
        helpers.print_subtask_negative('Cookie missing attribute: HttpOnly')
        vuln_file = open('nikto/vulnerabilities/missing-cookie-attribute-httponly.txt', 'a')
        vuln_file.write(target + ':' + port + '\n')
        vuln_file.close()

#####################
# ARGUMENT PARSING
#####################
# Set up command line argument parsing
parser = argparse.ArgumentParser(description='A simple python scrupt which runs nikto against a list of hosts.')
parser.add_argument('targets', help="A file containing a list of hostname/IP:port")
parser.add_argument('-p', '--print', action="store_true", help='Print the output of each scan.')
parser.add_argument('-i', '--interpret', action="store_true", help='Interpret scan output and produce a set of lists of simple findings.')
# Parse the supplied arguments
args = parser.parse_args()

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print (__name__)
