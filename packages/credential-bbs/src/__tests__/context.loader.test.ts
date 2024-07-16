import { ContextDoc } from '../types.js'
import { BbsContextLoader } from '../bbs-context-loader.js'
import { BbsDefaultContexts } from '../bbs-default-contexts.js'

describe('credential-bbs context loader', () => {
  const customContext: Record<string, ContextDoc> = {
    'https://example.com/custom/context': {
      '@context': {
        '@version': 1.1,
        id: '@id',
        type: '@type',
        nothing: 'https://example.com/nothing',
      },
    },
  }

  it('loads custom context from record', async () => {
    expect.assertions(2)
    const loader = new BbsContextLoader({ contextsPaths: [customContext] })
    expect(loader.has('https://example.com/custom/context')).toBe(true)
    await expect(loader.get('https://example.com/custom/context')).resolves.toEqual({
      '@context': {
        '@version': 1.1,
        id: '@id',
        type: '@type',
        nothing: 'https://example.com/nothing',
      },
    })
  })

  it('loads context from default map', async () => {
    expect.assertions(2)
    const loader = new BbsContextLoader({ contextsPaths: [BbsDefaultContexts] })
    expect(loader.has('https://www.w3.org/2018/credentials/v1')).toBe(true)

    const credsContext = await loader.get('https://www.w3.org/2018/credentials/v1')
    expect(credsContext['@context']).toBeDefined()
  })
})
