#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  HELPERS                                                                      #
#                                                                               #
#  A collection of helper functions that are used throughout the tools in this  #
#  repository.
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 0.2                                                                 #
#  Last modified: 14-02-2018                                                    #
#                                                                               #
#  TODO: Everything                                                             #
#                                                                               #
#################################################################################

#####################
# IMPORTS
#####################
import ipaddress
import os
import pathlib
import re
import subprocess
import unicodedata


#####################
# GLOBALS
#####################
web_ports = [80, 443, 8080]

#####################
# HELPERS
#####################

## Print functions
def print_script_message(script, version, tagline):
    divider = '-' * (len(tagline) + 5)
    print(divider)
    print(' ' + script.upper() + ' version ' + version)
    print(' ' + tagline)
    print(divider)
    print('')

def print_heading(heading):
    print('#################################')
    print('# ' + heading)
    print('#################################')

def print_task_positive(task):
    print('[+] ' + task)

def print_task_negative(task):
    print('[-] ' + task)

def print_subtask_positive(task):
    print('  [+] ' + task)

def print_subtask_negative(task):
    print('  [-] ' + task)

## Remove ansi encoding for string comparison
def remove_ansi(string):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', string)

## Remove control characters
def remove_control_characters(s):
    return "".join(ch for ch in s if unicodedata.category(ch)[0]!="C")

## Get common web ports
def get_web_ports(scan_output):
    # Array of web ports returned by scan
    scanned_web_ports = []
    # Test each known web port
    for port in web_ports:
        # Construct the port string
        port_string = (str(port) + '/tcp')
        if(port_string in scan_output):
            scanned_web_ports.append(port)
    # Return the array
    return scanned_web_ports

## Make a direcotry in a clean way
def mkdir(dir_name):
    pathlib.Path(os.getcwd() + '/' + dir_name).mkdir(parents=True, exist_ok=True)

## Run updates of the local kali machine
def update():
    provision_project = input('Would you like to run updates before provisioning the project? (y/n) ')
    if(provision_project == 'y' or provision_project == 'Y'):
        print('------ Updating Kali ------')
        print('Running updates...')
        subprocess.run(['apt-get', 'update', '-y', '-q'])
        subprocess.run(['apt-get', 'upgrade', '-y', '-q'])
    else:
        print('Okay, carrying on...')
    print()

## Test an IP address for validity
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
