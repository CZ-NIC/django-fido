import 'core-js/stable'
import 'regenerator-runtime/runtime'

import {
    DJANGO_FIDO_FORM_ID,
    FIDO2_AUTHENTICATION_REQUEST,
    FIDO2_REGISTRATION_REQUEST,
    _arrayBufferToBase64,
    _base64ToArrayBuffer,
    addFido2Error,
    clearFido2Errors,
    createTranslations,
    fido2ErrorResponseCallback,
    sendFido2RegistrationRequest,
    startFido2,
} from './fido2-utils'

document.addEventListener('DOMContentLoaded', () => {
    createTranslations()
    startFido2()
}, false)

export {
    DJANGO_FIDO_FORM_ID,
    FIDO2_AUTHENTICATION_REQUEST,
    FIDO2_REGISTRATION_REQUEST,
    _arrayBufferToBase64,
    _base64ToArrayBuffer,
    addFido2Error,
    clearFido2Errors,
    createTranslations,
    fido2ErrorResponseCallback,
    sendFido2RegistrationRequest,
    startFido2,
}
