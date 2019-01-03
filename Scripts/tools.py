#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  TOOLS                                                                        #
#                                                                               #
#  Pull down my most-used git repos.                                            #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 06-10-2018                                                    #
#                                                                               #
#################################################################################
name = 'TOOLS'
version = '1.0.0'
tagline = 'Download a list of useful git repositories.'

#####################
# IMPORTS
#####################
import subprocess
from Modules import helpers

#####################
# REPOSITORIES
#####################
repositories = [
    'https://github.com/codingo/Reconnoitre.git',
    'https://github.com/danielmiessler/SecLists.git',
    'https://github.com/superkojiman/onetwopunch.git'
]

#####################
# FUNCTIONS
##################### 
def main():
    # Print script message
    helpers.print_script_message(name, version, tagline)

    # Download git repos
    for repo in repositories:
        helpers.print_task_positive('Cloning ' + repo)
        subprocess.run(['git', 'clone', repo])
        print('')

#####################
# MAIN
#####################
if __name__ =='__main__':
    main()
else:
    print (__name__)
