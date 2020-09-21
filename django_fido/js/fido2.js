const DJANGO_FIDO_FORM_ID = 'django-fido-form'
const DJANGO_FIDO_ERROR_LIST_ID = 'django-fido-errors'
// FIDO 2 request identifiers - shared between code and JS
const FIDO2_REGISTRATION_REQUEST = 'registration'
const FIDO2_AUTHENTICATION_REQUEST = 'authentication'

const TRANSLATIONS = {}

function createTranslations() {
    TRANSLATIONS.ERROR_MESSAGES = {
        'NotSupportedError': gettext('The security token (FIDO 2) does not support the requested operation.'),
        'SecurityError': gettext('The request is insecure.'),
        'AbortError': gettext('The request has been aborted.'),
        'ConstraintError': gettext('The security token (FIDO 2) does not meet required criteria.'),
        'NotAllowedError': gettext('Something went wrong, or the time limit was reached. Please, try it again.'),
        'NoAuthenticatorsError': gettext('No compatible security keys are registered in your account.'),
    }
    TRANSLATIONS.GENERIC_ERROR_MESSAGE = gettext('An unknown error has occurred.')
    TRANSLATIONS.FIDO2_NOT_AVAILABLE = gettext('FIDO 2 is not available. Your browser may not support it'
                                        + ' or your connection is not secure.')
    TRANSLATIONS.UKNOWN_FIDO_REQUEST = gettext('Unknown FIDO 2 request.')
}

function addFido2Error(message) {
    let error_list = document.getElementById(DJANGO_FIDO_ERROR_LIST_ID)
    if (!error_list) {
        const form = document.getElementById(DJANGO_FIDO_FORM_ID)
        error_list = document.createElement('ul')
        error_list.id = DJANGO_FIDO_ERROR_LIST_ID
        form.appendChild(error_list)
    }
    const new_item = document.createElement('li')
    new_item.appendChild(document.createTextNode(message))
    error_list.appendChild(new_item)
}

function clearFido2Errors() {
    const error_list = document.getElementById(DJANGO_FIDO_ERROR_LIST_ID)
    if (error_list) {
        while (error_list.firstChild) {
            error_list.removeChild(error_list.lastChild)
        }
    }
}

function isFido2Availabile() {
    return navigator.credentials !== undefined
}

// https://stackoverflow.com/a/9458996/2440346
function _arrayBufferToBase64(buffer) {
    let binary = ''
    const bytes = new Uint8Array(buffer)
    for (const byte of bytes)
        binary += String.fromCharCode(byte)
    return window.btoa(binary)
}

// https://stackoverflow.com/a/21797381/2440346
function _base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64)
    const bytes = new Uint8Array(binary_string.length)
    for (let i = 0; i < binary_string.length; i++) {
        bytes[i] = binary_string.charCodeAt(i)
    }
    return bytes
}

function fido2SuccessRegistrationCallback(attestation) {
    const form = document.getElementById(DJANGO_FIDO_FORM_ID)
    form.client_data.value = _arrayBufferToBase64(attestation.response.clientDataJSON)
    form.attestation.value = _arrayBufferToBase64(attestation.response.attestationObject)
    form.submit()
}

function fido2SuccessAuthenticationCallback(assertion) {
    const form = document.getElementById(DJANGO_FIDO_FORM_ID)
    form.client_data.value = _arrayBufferToBase64(assertion.response.clientDataJSON)
    form.credential_id.value = _arrayBufferToBase64(assertion.rawId)
    form.authenticator_data.value = _arrayBufferToBase64(assertion.response.authenticatorData)
    form.signature.value = _arrayBufferToBase64(assertion.response.signature)
    form.submit()
}

function fido2ErrorResponseCallback(error) {
    let message = TRANSLATIONS.GENERIC_ERROR_MESSAGE
    if (error && TRANSLATIONS.ERROR_MESSAGES[error.name]) {
        message = TRANSLATIONS.ERROR_MESSAGES[error.name]
    }
    addFido2Error(message)

    window.dispatchEvent(new Event('on-close-fido-window'))
}

async function sendFido2Request(url, is_registration, credenetials_name, form_data = '') {
    clearFido2Errors()
    const response = await fetch(`${url}?${form_data}`)

    window.dispatchEvent(new Event('on-activatation-fido-window'))

    if (response.ok) {
        const fido2_request = await response.json()
        const publicKey = fido2_request.publicKey
        publicKey.challenge = _base64ToArrayBuffer(publicKey.challenge)
        if (is_registration)
            publicKey.user.id = new TextEncoder().encode(publicKey.user.id)

        // Decode credentials
        const decoded_credentials = []
        for (const credential of publicKey[credenetials_name]){
            credential.id = _base64ToArrayBuffer(credential.id)
            decoded_credentials.push(credential)
        }
        publicKey[credenetials_name] = decoded_credentials

        try {
            if (is_registration){
                const result = await navigator.credentials.create({ publicKey })
                fido2SuccessRegistrationCallback(result)
            } else {
                const result = await navigator.credentials.get({ publicKey })
                fido2SuccessAuthenticationCallback(result)
            }
        } catch (error) {
            fido2ErrorResponseCallback(error)
        }
    } else {
        try {
            const error_response = await response.json()
            fido2ErrorResponseCallback({name: error_response.error_code})
        } catch (error) {
            fido2ErrorResponseCallback(null)
        }
    }
}

async function sendFido2RegistrationRequest(url, form_data) {
    await sendFido2Request(url, true, 'excludeCredentials', form_data)
}

async function sendFido2AuthenticationRequest(url, form_data) {
    await sendFido2Request(url, false, 'allowCredentials', form_data)
}

async function startFido2() {
    const form = document.getElementById(DJANGO_FIDO_FORM_ID)
    if (!form)
        return // Silently skip if not on correct page.

    if (!isFido2Availabile()) {
        addFido2Error(TRANSLATIONS.FIDO2_NOT_AVAILABLE)
        return
    }

    if (form.dataset.mode === FIDO2_AUTHENTICATION_REQUEST) {
        const submit_button = document.getElementById('submit-button')
        if (submit_button) {
            submit_button.addEventListener('click', async e => {
                e.preventDefault()

                let form_data = ''
                const username_field = form.querySelector('[name=username]')
                if (username_field)
                    form_data = `username=${username_field.value}`

                await sendFido2AuthenticationRequest(form.dataset.url, form_data)
            })
        }
        if (form.dataset.autosubmitOff === undefined) {
            // autosubmit the authentication request unless form defines `data-autosubmit-off` attribute
            await sendFido2AuthenticationRequest(form.dataset.url)
        }
    } else if (form.dataset.mode === FIDO2_REGISTRATION_REQUEST) {
        const submit_button = document.getElementById('submit-button')
        if (submit_button) {
            submit_button.addEventListener('click', async e => {
                e.preventDefault()

                let form_data = ''
                const user_field = form.querySelector('[name=user]')
                if (user_field)
                    form_data = `user=${user_field.value}`

                await sendFido2RegistrationRequest(form.dataset.url, form_data)
            })
        }
    } else {
        addFido2Error(TRANSLATIONS.UKNOWN_FIDO_REQUEST)
    }
}

document.addEventListener('DOMContentLoaded', () => {
    createTranslations()
    startFido2()
}, false)

export {startFido2, FIDO2_REGISTRATION_REQUEST, FIDO2_AUTHENTICATION_REQUEST, addFido2Error, clearFido2Errors}
