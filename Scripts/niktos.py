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
                nikto_outfile = open('nikto/' + target_dash + '-' + port + '.txt', 'w')
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

    # Process the scan output
    # Server header
    if (output.find('Server:') != -1):
        helpers.print_subtask_negative('Server header')
        vuln_file = open('nikto/vulnerabilities/server-headers.txt', 'a')
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
