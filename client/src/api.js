import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

let csrfToken = null

export async function fetchCsrfToken() {
  const res = await api.get('/csrf-token')
  csrfToken = res.data.csrfToken
  return csrfToken
}

const MUTATING = ['post', 'put', 'patch', 'delete']

// Attach the anti-CSRF token to every state-changing request. The attacker's
// forged form cannot set this header, which is what defeats the forgery.
api.interceptors.request.use(async (config) => {
  if (MUTATING.includes((config.method || '').toLowerCase())) {
    if (!csrfToken) await fetchCsrfToken()
    config.headers['x-csrf-token'] = csrfToken
  }
  return config
})

// The token is bound to the session, so refresh it once if it went stale.
api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const cfg = error.config
    if (error.response?.status === 403
      && error.response?.data?.message === 'Invalid or missing CSRF token'
      && cfg && !cfg.__csrfRetried) {
      cfg.__csrfRetried = true
      await fetchCsrfToken()
      cfg.headers['x-csrf-token'] = csrfToken
      return api(cfg)
    }
    return Promise.reject(error)
  }
)
