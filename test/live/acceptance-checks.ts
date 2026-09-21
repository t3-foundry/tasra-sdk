/** Observe explicit authorization refusals; network errors never count as denial. */
export async function expectDenial(operation: () => Promise<unknown>): Promise<number[]> {
  const originalFetch = globalThis.fetch
  const statuses: number[] = []
  let transportFailed = false
  globalThis.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    const authorization = /\/v1\/(committee-authorize|committee\/(sign|decrypt))$/.test(url.pathname)
    try {
      const response = await originalFetch(input, init)
      if (authorization) statuses.push(response.status)
      return response
    } catch (error) { transportFailed = true; throw error }
  }
  let rejected = false
  try { await operation() } catch { rejected = true }
  finally { globalThis.fetch = originalFetch }
  if (!rejected || transportFailed || !statuses.length || !statuses.every(status => status === 401 || status === 403)) {
    throw new Error('Expected explicit authorization refusal; success, transport/configuration errors, and mixed responses are not acceptance')
  }
  return statuses
}
