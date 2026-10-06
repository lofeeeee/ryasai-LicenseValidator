/** License Manager configuration (environment variables / .env). */

const env = process.env

/** Accepts the legacy SQLAlchemy URL (sqlite+aiosqlite:///./data/license.db) or a plain file path. */
function resolveDatabasePath(url: string): string {
  const match = url.match(/^sqlite(?:\+\w+)?:\/\/\/(.+)$/)
  return match ? match[1] : url
}

/** A whole number >= 0 from the environment, or the fallback when unset or invalid. */
function count<T extends number | null>(value: string | undefined, fallback: T): number | T {
  const n = Number(value)
  return value !== undefined && value.trim() !== '' && Number.isInteger(n) && n >= 0 ? n : fallback
}

/** Placeholder secret: request signing is refused while SECRET_KEY still has this value. */
export const DEFAULT_SECRET_KEY = 'change-me-in-production-super-secret'

export const settings = {
  APP_NAME: env.APP_NAME ?? 'License Manager',
  APP_VERSION: env.APP_VERSION ?? '2.0.0',
  // Shared with the apps that send signed requests (license renewal)
  SECRET_KEY: env.SECRET_KEY ?? DEFAULT_SECRET_KEY,

  // Database (SQLite — lightweight, no external service needed)
  DATABASE_PATH: resolveDatabasePath(env.DATABASE_URL ?? './data/license.db'),

  // JWT (HS256)
  JWT_SECRET: env.JWT_SECRET ?? 'jwt-secret-key-change-me',
  JWT_EXPIRE_HOURS: Number(env.JWT_EXPIRE_HOURS ?? 24),

  // The only email the first-time setup accepts (the password is chosen during setup)
  ADMIN_EMAIL: env.ADMIN_EMAIL ?? 'admin@ryasai.com',

  // CORS
  CORS_ORIGINS: env.CORS_ORIGINS ?? '', // Comma-separated additional origins

  // Reverse proxies in front of this server that append to X-Forwarded-For.
  // Unset (null) = detect: the header is believed only when the connection comes from a local proxy.
  // 0 = clients connect directly, so the header is always ignored and the socket address is used.
  TRUSTED_PROXY_HOPS: count(env.TRUSTED_PROXY_HOPS, null),

  // An active machine not seen for this many days gives its slot back. 0 = never.
  MACHINE_STALE_DAYS: count(env.MACHINE_STALE_DAYS, 30),

  // Validation logs older than this many days are deleted. 0 = keep forever.
  LOG_RETENTION_DAYS: count(env.LOG_RETENTION_DAYS, 0),

  // Ed25519 signing key (DER-encoded, hex). Used to sign validation responses.
  // Generate: node -e "const c=require('crypto');const{publicKey:k1,privateKey:k2}=c.generateKeyPairSync('ed25519');console.log(k1.export({type:'spki',format:'der'}).toString('hex'));console.log(k2.export({type:'pkcs8',format:'der'}).toString('hex'))"
  LICENSE_SIGNING_PRIVATE_KEY: env.LICENSE_SIGNING_PRIVATE_KEY ?? '',
}
