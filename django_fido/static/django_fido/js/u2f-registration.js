U2F_FORM_ID = 'django-fido-u2f-form'
U2F_ERROR_LIST_ID = 'django-fido-u2f-errors'
// U2F request identifiers - shared between code and JS
U2F_REGISTRATION_REQUEST = 'registration'
U2F_AUTHENTICATION_REQUEST = 'authentication'
// Timeout for the U2F request
U2F_TIMEOUT = 30


function addU2fError(message) {
    var error_list = document.getElementById(U2F_ERROR_LIST_ID);
    var new_item = document.createElement("li");
    new_item.appendChild(document.createTextNode(message));
    error_list.appendChild(new_item);
}

function isU2fAvailabile() {
    return !(typeof window.u2f === 'undefined');
};

function u2fResponseCallback(u2f_response) {
    if (u2f_response.errorCode) {
        addU2fError('An error ' + u2f_response.errorCode + ' occured.');
        return
    }
    var form = document.getElementById(U2F_FORM_ID);
    form.u2f_response.value = JSON.stringify(u2f_response);
    form.submit();
}

function u2fRegistrationRequestCallback() {
    if (this.readyState == 4 && this.status == 200) {
        var u2f_request = JSON.parse(this.responseText);
        u2f.register(u2f_request.appId, u2f_request.registerRequests, u2f_request.registeredKeys, u2fResponseCallback, U2F_TIMEOUT);
    };
}

function u2fAuthenticationRequestCallback() {
    if (this.readyState == 4 && this.status == 200) {
        var u2f_request = JSON.parse(this.responseText);
        u2f.sign(u2f_request.appId, u2f_request.challenge, u2f_request.registeredKeys, u2fResponseCallback, U2F_TIMEOUT);
    };
}

function processU2fRequest(url, callback) {
    var http_request = new XMLHttpRequest();
    http_request.onreadystatechange = callback;
    http_request.open('GET', url, true);
    http_request.send();
};

function startU2f() {
    var form = document.getElementById(U2F_FORM_ID);
    if (!form) {
        // Silently skip if not on correct page.
        return
    };
    if (!isU2fAvailabile()) {
        addU2fError("U2F is not available");
        return
    };
    if (form.dataset.mode == U2F_AUTHENTICATION_REQUEST) {
        processU2fRequest(form.dataset.url, u2fAuthenticationRequestCallback);
    } else if (form.dataset.mode == U2F_REGISTRATION_REQUEST) {
        processU2fRequest(form.dataset.url, u2fRegistrationRequestCallback);
    } else {
        addU2fError("Unknown U2F request.");
    }
}

document.addEventListener('DOMContentLoaded', startU2f, false);
