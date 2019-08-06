DJANGO_FIDO_FORM_ID = 'django-fido-form'
DJANGO_FIDO_ERROR_LIST_ID = 'django-fido-errors'
// FIDO 2 request identifiers - shared between code and JS
FIDO2_REGISTRATION_REQUEST = 'registration'
FIDO2_AUTHENTICATION_REQUEST = 'authentication'

// Ensure gettext function exist
if (typeof(gettext) === "undefined") {
    gettext = function(msg) {
        return msg;
    };
}

ERROR_MESSAGES = {
    'NotSupportedError': "The security token (FIDO 2) does not support the requested operation.",
    'SecurityError': "The request is insecure.",
    'AbortError': "The request has been aborted.",
    'ConstraintError': "The security token (FIDO 2) does not meet required criteria.",
    'NotAllowedError': "The request has been refused either by you, your browser, or your operating system. "
                               + "Or the request timed out."
}
GENERIC_ERROR_MESSAGE = "An unknown error has occurred.";

function addFido2Error(message) {
    var error_list = document.getElementById(DJANGO_FIDO_ERROR_LIST_ID);
    var new_item = document.createElement("li");
    new_item.appendChild(document.createTextNode(message));
    error_list.appendChild(new_item);
}

function isFido2Availabile() {
    return !(typeof navigator.credentials === 'undefined');
};

// https://stackoverflow.com/a/9458996/2440346
function bytes_to_base64(buffer) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}

// https://stackoverflow.com/a/21797381/2440346
function base64_to_bytes(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

function fido2SuccessRegistrationCallback(attestation) {
    var form = document.getElementById(DJANGO_FIDO_FORM_ID);
    form.client_data.value = bytes_to_base64(attestation.response.clientDataJSON)
    form.attestation.value = bytes_to_base64(attestation.response.attestationObject)
    form.submit();
}

function fido2SuccessAuthenticationCallback(assertion) {
    var form = document.getElementById(DJANGO_FIDO_FORM_ID);
    form.client_data.value = bytes_to_base64(assertion.response.clientDataJSON)
    form.credential_id.value = bytes_to_base64(assertion.rawId)
    form.authenticator_data.value = bytes_to_base64(assertion.response.authenticatorData)
    form.signature.value = bytes_to_base64(assertion.response.signature)
    form.submit();
}

function fido2ErrorResponseCallback(error) {
    var message = gettext(GENERIC_ERROR_MESSAGE);
    if (ERROR_MESSAGES.hasOwnProperty(error.name)) {
        message = gettext(ERROR_MESSAGES[error.name])
    }
    addFido2Error(message)
    if (typeof closeFidoWindow === 'function') {
        closeFidoWindow();
    }
}

function fido2RegistrationRequestCallback() {
    if (typeof activeFidoWindow === 'function') {
        activeFidoWindow();
    }
    if (this.readyState == 4 && this.status == 200) {
        var fido2_request = JSON.parse(this.responseText);
        var encoder = new TextEncoder()
        var publicKey = fido2_request.publicKey
        publicKey.challenge = base64_to_bytes(publicKey.challenge)
        publicKey.user.id = encoder.encode(publicKey.user.id)
        // Decode excludeCredentials
        var decoded_credentials = []
        for (var i = 0; i < publicKey.excludeCredentials.length; i++) {
            var credential = publicKey.excludeCredentials[i]
            credential.id = base64_to_bytes(credential.id)
            decoded_credentials.push(credential)
        }
        publicKey.excludeCredentials = decoded_credentials

        navigator.credentials.create({ publicKey }).then(fido2SuccessRegistrationCallback).catch(fido2ErrorResponseCallback);
    };
}

function fido2AuthenticationRequestCallback() {
    if (typeof activeFidoWindow === 'function') {
        activeFidoWindow();
    }
    if (this.readyState == 4 && this.status == 200) {
        var fido2_request = JSON.parse(this.responseText);
        var publicKey = fido2_request.publicKey
        publicKey.challenge = base64_to_bytes(publicKey.challenge)
        // Decode allowCredentials
        var decoded_credentials = []
        for (var i = 0; i < publicKey.allowCredentials.length; i++) {
            var credential = publicKey.allowCredentials[i]
            credential.id = base64_to_bytes(credential.id)
            decoded_credentials.push(credential)
        }
        publicKey.allowCredentials = decoded_credentials

        navigator.credentials.get({ publicKey }).then(fido2SuccessAuthenticationCallback).catch(fido2ErrorResponseCallback);
    };
}

function processFido2Request(url, callback) {
    var http_request = new XMLHttpRequest();
    http_request.onreadystatechange = callback;
    http_request.open('GET', url, true);
    http_request.send();
};

function startFido2() {
    var form = document.getElementById(DJANGO_FIDO_FORM_ID);
    var sb = document.getElementById('submit-button');
    // If is empty values, submit button reload page
    sb.addEventListener('click', function(e) {
        if(form.client_data.value === '' || form.credential_id.value === '' || form.authenticator_data.value === '' || form.signature.value === '') {
            e.preventDefault();
            location.reload();
        }
    });
    if (!form) {
        // Silently skip if not on correct page.
        return
    };
    if (!isFido2Availabile()) {
        addFido2Error(
            gettext("FIDO 2 is not available. Your browser may not support it or your connection is not secure."));
        return
    };
    if (form.dataset.mode == FIDO2_AUTHENTICATION_REQUEST) {
        processFido2Request(form.dataset.url, fido2AuthenticationRequestCallback);
    } else if (form.dataset.mode == FIDO2_REGISTRATION_REQUEST) {
        processFido2Request(form.dataset.url, fido2RegistrationRequestCallback);
    } else {
        addFido2Error(gettext("Unknown FIDO 2 request."));
    }
}

document.addEventListener('DOMContentLoaded', startFido2, false);
