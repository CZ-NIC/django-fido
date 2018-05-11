const U2F_FORM_ID = 'django-fido-u2f-form'
const U2F_ERROR_LIST_ID = 'django-fido-u2f-errors'
// U2F request identifiers - shared between code and JS
const U2F_REGISTRATION_REQUEST = 'registration'
const U2F_AUTHENTICATION_REQUEST = 'authentication'
// Timeout for the U2F request
const U2F_TIMEOUT = 30
const U2F_ERROR_CODES = {
    1: 'An error occurred while processing U2F request',
    2: 'U2F request cannot be processed.',
    3: 'Your configuration for U2F is not supported.',
    4: 'The presented device is not eligible for this request.',
    5: 'U2F request timed out.'
}

function addU2fError(message) {
    const error_list = document.getElementById(U2F_ERROR_LIST_ID);
    const new_item = document.createElement("li");
    new_item.classList.add('error');
    new_item.appendChild(document.createTextNode(gettext(message)));
    error_list.appendChild(new_item);
}

function isU2fAvailabile() {
    return (typeof window.u2f !== 'undefined');
}

function u2fResponseCallback(u2f_response) {
    if (u2f_response.errorCode) {
        addU2fError(U2F_ERROR_CODES[u2f_response.errorCode]);
        return
    }
    const form = document.getElementById(U2F_FORM_ID);
    form.u2f_response.value = JSON.stringify(u2f_response);
    form.submit();
}

function processU2fRequest(formDataset) {
    const http_request = new XMLHttpRequest();
    http_request.onreadystatechange = () => {
        if (http_request.readyState === 4 && http_request.status === 200) {
            const u2f_request = JSON.parse(http_request.responseText);
            if (formDataset.mode === U2F_AUTHENTICATION_REQUEST) {
                u2f.sign(u2f_request.appId, u2f_request.challenge, u2f_request.registeredKeys, u2fResponseCallback, U2F_TIMEOUT);
            } else if (formDataset.mode === U2F_REGISTRATION_REQUEST) {
                u2f.register(u2f_request.appId, u2f_request.registerRequests, u2f_request.registeredKeys, u2fResponseCallback, U2F_TIMEOUT);
            } else {
                addU2fError("Unknown U2F request.");
                return
            }
        }
    };
    http_request.open('GET', formDataset.url, true);
    http_request.send();
}

function startU2f() {
    const form = document.getElementById(U2F_FORM_ID);
    if (!form) {
        // Silently skip if not on correct page.
        return
    }
    if (!isU2fAvailabile()) {
        addU2fError("U2F is not available");
        return
    }
    if (form.dataset.mode) {
        processU2fRequest(form.dataset);
    }
}

document.addEventListener('DOMContentLoaded', startU2f, false);
