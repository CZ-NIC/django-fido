import startFido2 from '../js/fido2'
import fetchMock from 'fetch-mock'
import '@babel/polyfill'
import {TextEncoder} from 'util'

describe('Fido 2', () => {

    afterEach(() => {
        document.getElementsByTagName('html')[0].innerHTML = ''
    })

    global.TextEncoder = TextEncoder

    navigator.credentials = {
        get: jest.fn(public_key => {
            expect(public_key).toMatchSnapshot()
            return {response: {}}
        }),
        create: jest.fn(public_key => {
            expect(public_key).toMatchSnapshot()
            return {response: {}}
        }),
    }


    fetchMock.mock('/data', {
        publicKey: {
            rpId:'mojeid.cz',
            challenge:'wuhwhe==',
            allowCredentials:[{type:'public-key', id:'wuheehe'}],
            excludeCredentials:[{type:'public-key', id:'wuheehe'}],
            timeout:30000,
            userVerification:'preferred',
            user: {id: 'id'},
        },
    })

    async function testWorkflow(mode) {
        const form = document.createElement('form')
        form.id = 'django-fido-form'
        form.dataset.mode = mode
        form.dataset.url = '/data'
        form.client_data = {value: 'client data'}
        form.credential_id = {value: 'credential_id'}
        form.authenticator_data = {value: 'authenticator_data'}
        form.signature = {value: 'signature'}
        form.attestation = {}
        form.submit = jest.fn()

        const submit_button = document.createElement('button')
        submit_button.id = 'submit-button'

        document.getElementsByTagName('body')[0].appendChild(form)
        document.getElementsByTagName('body')[0].appendChild(submit_button)

        await startFido2()

        if (mode === 'registration') {
            expect(navigator.credentials.create).toHaveBeenCalledTimes(1)
        } else if (mode === 'authentication'){
            expect(navigator.credentials.get).toHaveBeenCalledTimes(1)
        }
        expect(form.submit).toHaveBeenCalledTimes(1)
    }

    test('auth workflow', async() => {
        await testWorkflow('authentication')
    })

    test('registration workflow', async() => {
        await testWorkflow('registration')
    })

})
