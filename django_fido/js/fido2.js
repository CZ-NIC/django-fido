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
        'NotAllowedError': gettext('The request has been refused either by you, your browser, or your'
                                   + ' operating system. Or the request timed out.'),
    }
    TRANSLATIONS.GENERIC_ERROR_MESSAGE = gettext('An unknown error has occurred.')
    TRANSLATIONS.FIDO2_NOT_AVAILABLE = gettext('FIDO 2 is not available. Your browser may not support it'
                                        + ' or your connection is not secure.')
    TRANSLATIONS.UKNOWN_FIDO_REQUEST = gettext('Unknown FIDO 2 request.')
}

function addFido2Error(message) {
    const error_list = document.getElementById(DJANGO_FIDO_ERROR_LIST_ID)
    const new_item = document.createElement('li')
    new_item.appendChild(document.createTextNode(message))
    error_list.appendChild(new_item)
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
    if (TRANSLATIONS.ERROR_MESSAGES[error.name]) {
        message = TRANSLATIONS.ERROR_MESSAGES[error.name]
    }
    addFido2Error(message)

    window.dispatchEvent(new Event('on-close-fido-window'))
}

async function sendFido2Request(url, is_registration, credenetials_name) {
    const response = await fetch(url)

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
    }
}

async function sendFido2RegistrationRequest(url) {
    await sendFido2Request(url, true, 'excludeCredentials')
}

async function sendFido2AuthenticationRequest(url) {
    await sendFido2Request(url, false, 'allowCredentials')
}

async function startFido2() {
    const form = document.getElementById(DJANGO_FIDO_FORM_ID)
    if (!form)
        return // Silently skip if not on correct page.

    const submit_button = document.getElementById('submit-button')
    // If is empty values, submit button reload page
    submit_button.addEventListener('click', e => {
        if (form.client_data.value === '' || form.credential_id.value === '' ||
            form.authenticator_data.value === '' || form.signature.value === '')
        {
            e.preventDefault()
            location.reload()
        }
    })

    if (!isFido2Availabile()) {
        addFido2Error(TRANSLATIONS.FIDO2_NOT_AVAILABLE)
        return
    }
    if (form.dataset.mode === FIDO2_AUTHENTICATION_REQUEST) {
        await sendFido2AuthenticationRequest(form.dataset.url)
    } else if (form.dataset.mode === FIDO2_REGISTRATION_REQUEST) {
        await sendFido2RegistrationRequest(form.dataset.url)
    } else {
        addFido2Error(TRANSLATIONS.UKNOWN_FIDO_REQUEST)
    }
}

document.addEventListener('DOMContentLoaded', () => {
    createTranslations()
    startFido2()
}, false)

export default startFido2
