#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  PROVISION                                                                    #
#                                                                               #
#  A script which creates a filestructure to store findings.                    #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 06-04-2018                                                    #
#                                                                               #
#################################################################################
name = 'PROVISION'
version = '1.0.0'
tagline = 'A script which creates a filestructure to store findings.'

#####################
# IMPORTS
#####################
import subprocess
import os
from enum import Enum
from Modules import helpers

#####################
# VARIABLES
#####################
class TestType(Enum):
    EXTERNAL = 1
    WEB_APPLICATION = 2

#####################
# FUNCTIONS
#####################
def main():
    # Print messages
    helpers.print_script_message(name, version, tagline)

    # Collect project information
    print('------ Project configuration ------')
    project_number = input('Project number: ')
    client_name = input('Client name: ')
    project_name = input('Project name: ')

    # Keep asking for the number of packages until an int is provided
    while True:    
        try:
            num_packages = int(input('Number of work packages: '))
            break
        except ValueError:
            print('You need to enter a number')
            print('')

    # Sanitise client and project names
    project_name = project_name.replace(' ','-')
    client_name = client_name.replace(' ','-')

    # Create the project's directory
    project_directory = project_number + '-' + client_name + '-' + project_name
    os.mkdir(os.getcwd() + '/' + project_directory)
    os.chdir(os.getcwd() + '/' + project_directory)

    print('')
    print('------ Creating work packages ------')

    if(int(num_packages) == 1):
        create_workpackage()
    else:       
        for wp in range(0, int(num_packages)):
            # Create work package directories
            wp_number = input('Work package number: ')
            wp_name = input('Work package name: ').replace(' ', '-')
            os.mkdir(os.getcwd() + '/WP' + wp_number + '-' + wp_name)
            os.chdir(os.getcwd() + '/WP' + wp_number + '-' + wp_name)

            # Make wthe workpackage subdirectories
            create_workpackage()

    print('Happy hacking!')

def create_workpackage():
    print('Available test types:')
    print('  1) External Penetration Test')
    print('  2) Web Application Penetration Test')
    test_type = input('What type of test is this? ')

    if (int(test_type) == TestType.EXTERNAL.value):
        os.mkdir(os.getcwd() + '/1.information-gathering')
        os.mkdir(os.getcwd() + '/2.scanning-and-enumeration')
        os.mkdir(os.getcwd() + '/3.metasploit')
        os.mkdir(os.getcwd() + '/4.manual-exploit')
        os.mkdir(os.getcwd() + '/5.password-brute-force')
        os.mkdir(os.getcwd() + '/screenshots')
        os.mkdir(os.getcwd() + '/client-information')

    if (int(test_type) == TestType.WEB_APPLICATION.value):
        os.mkdir(os.getcwd() + '/1.information-gathering')
        os.mkdir(os.getcwd() + '/2.scanning-and-enumeration')
        os.mkdir(os.getcwd() + '/3.transport-security')
        os.mkdir(os.getcwd() + '/4.session-management')
        os.mkdir(os.getcwd() + '/5.authentication-testing')
        os.mkdir(os.getcwd() + '/6.authorisation-bl')
        os.mkdir(os.getcwd() + '/7.input-validation')
        os.mkdir(os.getcwd() + '/screenshots')
        os.mkdir(os.getcwd() + '/client-information')

    print('')
    os.chdir(os.getcwd() + '/..')

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
