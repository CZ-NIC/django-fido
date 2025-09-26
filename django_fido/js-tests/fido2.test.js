import {
  startFido2,
  FIDO2_REGISTRATION_REQUEST,
  FIDO2_AUTHENTICATION_REQUEST,
  addFido2Error,
  clearFido2Errors,
} from '../js/fido2-utils'

beforeEach(() => {
  fetch.resetMocks()
  fetch.mockResponse(
    JSON.stringify({
      publicKey: {
        rpId: 'mojeid.cz',
        challenge: 'wuhwhe==',
        allowCredentials: [{ type: 'public-key', id: 'wuheehe' }],
        excludeCredentials: [{ type: 'public-key', id: 'wuheehe' }],
        timeout: 30000,
        userVerification: 'preferred',
        user: { id: 'id' },
      },
    })
  )
})

describe('Fido 2', () => {
  afterEach(() => {
    document.getElementsByTagName('html')[0].innerHTML = ''
  })

  navigator.credentials = {
    get: vi.fn(public_key => {
      expect(public_key).toMatchSnapshot()
      return { response: {} }
    }),
    create: vi.fn(public_key => {
      expect(public_key).toMatchSnapshot()
      return { response: {} }
    }),
  }

  async function testWorkflow(mode) {
    const form = document.createElement('form')
    form.id = 'django-fido-form'
    form.dataset.mode = mode
    form.dataset.url = '/data'
    form.client_data = { value: 'client data' }
    form.credential_id = { value: 'credential_id' }
    form.authenticator_data = { value: 'authenticator_data' }
    form.signature = { value: 'signature' }
    form.attestation = {}
    form.user_handle = { value: '' }
    form.submit = vi.fn()

    const submit_button = document.createElement('button')
    submit_button.id = 'submit-button'

    document.body.appendChild(form)
    document.body.appendChild(submit_button)

    await startFido2()
    if (mode !== FIDO2_AUTHENTICATION_REQUEST) {
      await submit_button.click()
    }

    // wait a tick for async to resolve
    await new Promise(r => setTimeout(r, 1))

    if (mode === FIDO2_REGISTRATION_REQUEST) {
      expect(navigator.credentials.create).toHaveBeenCalledTimes(1)
    } else if (mode === FIDO2_AUTHENTICATION_REQUEST) {
      expect(navigator.credentials.get).toHaveBeenCalledTimes(1)
    }
    expect(form.submit).toHaveBeenCalledTimes(1)
  }

  test('auth workflow', async () => {
    await testWorkflow(FIDO2_AUTHENTICATION_REQUEST)
  })

  test('registration workflow', async () => {
    await testWorkflow(FIDO2_REGISTRATION_REQUEST)
  })

  test('addFido2Error', () => {
    const form = document.createElement('form')
    form.id = 'django-fido-form'
    document.body.appendChild(form)

    let error_list = document.getElementById('django-fido-errors')
    expect(error_list).toBe(null)

    addFido2Error('first error message')
    error_list = document.getElementById('django-fido-errors')
    expect(error_list).toMatchSnapshot()

    addFido2Error('second error message')
    expect(error_list).toMatchSnapshot()
  })

  test('clearFido2Errors', () => {
    let error_list = document.createElement('ul')
    error_list.id = 'django-fido-errors'
    const li = document.createElement('li')
    li.appendChild(document.createTextNode('first error message'))
    error_list.appendChild(li)
    const li2 = document.createElement('li')
    li2.appendChild(document.createTextNode('second error message'))
    error_list.appendChild(li2)
    document.body.appendChild(error_list)

    error_list = document.getElementById('django-fido-errors')
    expect(error_list).toMatchSnapshot()
    clearFido2Errors()
    expect(error_list).toMatchSnapshot()
  })
})
