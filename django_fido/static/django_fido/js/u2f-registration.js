class U2FRegistration {
    constructor () {
        this.U2F_FORM_ID = 'django-fido-u2f-form';
        this.U2F_ERROR_LIST_ID = 'django-fido-u2f-errors';
        this.U2F_REGISTRATION_REQUEST = 'registration';
        this.U2F_AUTHENTICATION_REQUEST = 'authentication';
        this.U2F_TIMEOUT = 30;
        this.U2F_ERROR_CODES = {
            1: gettext('An error occurred while processing U2F request'),
            2: gettext('U2F request cannot be processed.'),
            3: gettext('Your configuration for U2F is not supported.'),
            4: gettext('The presented device is not eligible for this request.'),
            5: gettext('U2F request timed out.')
        };
        this.u2fResponseCallback = this.u2fResponseCallback.bind(this);
        this.startU2f = this.startU2f.bind(this);
    }

    checkGettext() {
        if (typeof(gettext) === "undefined") {
            gettext = msg => msg;
        }
    }

    createErrorListElem() {
        const form = document.querySelector(`#${this.U2F_FORM_ID} fieldset`);
        const error_list = document.createElement("ul");
        error_list.id = this.U2F_ERROR_LIST_ID;
        form.prepend(error_list);
        return error_list;
    }

    addU2fError(message) {
        let error_list = document.getElementById(this.U2F_ERROR_LIST_ID) ? document.getElementById(this.U2F_ERROR_LIST_ID) : this.createErrorListElem();
        const new_item = document.createElement("li");
        new_item.classList.add('error');
        new_item.appendChild(document.createTextNode(message));
        error_list.appendChild(new_item);
    }

    isU2fAvailabile() {
        return (typeof window.u2f !== 'undefined');
    }

    u2fResponseCallback(u2f_response){
        if (u2f_response.errorCode) {
            this.addU2fError(this.U2F_ERROR_CODES[u2f_response.errorCode]);
            return
        }
        const form = document.getElementById(this.U2F_FORM_ID);
        form.u2f_response.value = JSON.stringify(u2f_response);
        form.submit();
    }

    processU2fRequest(formDataset) {
        fetch(formDataset.url, {
            method: 'get',
            credentials: 'same-origin'
        })
            .then((response) => {
                if (response.ok) {
                    return response.text();
                }
            })
            .then((text) => {
                const u2f_request = JSON.parse(text);
                if (formDataset.mode === this.U2F_AUTHENTICATION_REQUEST) {
                    u2f.sign(u2f_request.appId, u2f_request.challenge, u2f_request.registeredKeys, this.u2fResponseCallback, this.U2F_TIMEOUT);
                } else if (formDataset.mode === this.U2F_REGISTRATION_REQUEST) {
                    u2f.register(u2f_request.appId, u2f_request.registerRequests, u2f_request.registeredKeys, this.u2fResponseCallback, this.U2F_TIMEOUT);
                } else {
                    this.addU2fError(gettext("Unknown U2F request."));
                    return;
                }
            });
    }
    
    startU2f(){
        this.checkGettext();
        const form = document.getElementById(this.U2F_FORM_ID);
        if (!form) {
            // Silently skip if not on correct page.
            return
        }
        if (!this.isU2fAvailabile()) {
            this.addU2fError(gettext("U2F is not available"));
            return
        }
        if (form.dataset.mode) {
            this.processU2fRequest(form.dataset);
        }
    }

}

let reg = new U2FRegistration()
document.addEventListener('DOMContentLoaded', reg.startU2f, false);
