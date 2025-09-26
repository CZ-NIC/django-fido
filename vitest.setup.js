import createFetchMock from 'vitest-fetch-mock'
import { TextEncoder, TextDecoder } from 'util'

const fetchMocker = createFetchMock(vi)
fetchMocker.enableMocks()

global.TextEncoder = TextEncoder
global.TextDecoder = TextDecoder
