import {
  literalReadLists,
  literalWriteLists,
  readRulesOf,
  spelledOf,
  writeRootsOf,
} from './path-entries.js'
import { createHttpProxyServer } from './http-proxy.js'
import { assertTlsTerminationSupported } from './emitted-connection.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { createMuxProxyServer, type MuxProxyServer } from './mux-proxy.js'
import { listenInRange } from './listen-in-range.js'
import { SentinelRegistry } from './credential-sentinel.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from './credential-mask-files.js'
import { buildMaskedEnvVars } from './credential-mask-env.js'
import {
  AwsPairRegistry,
  createSigv4Planner,
  registerAwsPairs,
  type PlanSigv4,
} from './credential-aws-pairs.js'
import {
  createMitmCA,
  CRL_PATH,
  disposeMitmCA,
  disposeMitmCASync,
  type MitmCA,
} from './mitm-ca.js'
import { logForDebugging } from '../utils/debug.js'
import type { RipgrepConfig } from '../utils/ripgrep.js'
import { getPlatform, getWslVersion } from '../utils/platform.js'
import { randomBytes } from 'node:crypto'
import type {
  CredentialsConfig,
  FilesystemPathEntry,
  SandboxRuntimeConfig,
} from './sandbox-config.js'
import type {
  SandboxAskCallback,
  CredentialRestrictionConfig,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import type { WindowsBinShell } from './windows-sandbox-utils.js'
import {
  getDefaultWritePaths,
  attributionKeyFor,
  decodeSandboxedCommand,
  encodeSandboxedCommand,
} from './sandbox-utils.js'
import {
  activateLandstripSession,
  assertLandstripConfig,
  beginLandstripReset,
  beginLandstripWrap,
  landstripUnavailableReason,
  landstripProxyPortRange,
  quoteLandstripInvocation,
  wrapWithLandstrip,
} from './landstrip-sandbox-utils.js'
import { ownInstallWarning } from './own-files.js'
import {
  generateLogTag,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  SandboxViolationStore,
  sanitizeDenialReason,
  sanitizeUnregisteredCommandKey,
  shouldIgnoreViolation,
} from './sandbox-violation-store.js'
import type { MutateForwardedHeaders } from './request-filter.js'
import type { GetBodySubstitutions } from './body-substitution.js'
import {
  canonicalizeHost,
  isValidHost,
  redactUrl,
  resolveParentProxy,
} from './parent-proxy.js'
import {
  ALLOWED_DOMAIN_ENTRY_MESSAGE,
  isValidAllowedDomainEntry,
  matchesDomainPattern,
  matchesDomainPatternWithPort,
  stripDomainPatternPort,
} from './domain-pattern.js'
import type { DirectLookup, ResolvedParentProxy } from './parent-proxy.js'
import {
  createResolvedAddressGuard,
  isResolvedAddressDenied,
  type ResolvedAddressGuard,
} from './resolved-address-guard.js'
import { EOL } from 'node:os'
import { dirname } from 'node:path'
import { getJavaProxyAgentJarPathAsync } from './java-proxy-agent.js'

interface HostNetworkManagerContext {
  httpProxyPort: number
  socksProxyPort: number
}

// ============================================================================
// Private Module State
// ============================================================================

let config: SandboxRuntimeConfig | undefined
let httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
let socksProxyServer: SocksProxyWrapper | undefined
let muxProxyServer: MuxProxyServer | undefined
let managerContext: HostNetworkManagerContext | undefined
let initializationPromise: Promise<HostNetworkManagerContext> | undefined
let cleanupRegistered = false
let logMonitorShutdown: (() => void) | undefined
let ownInstallLogged = false
let parentProxy: ResolvedParentProxy | undefined
/** Read live through {@link directLookup}, so a config update applies to the next dial. */
let resolvedAddressGuard: ResolvedAddressGuard = createResolvedAddressGuard()
let mitmCA: MitmCA | undefined
/**
 * Resolved path of the JVM proxy agent jar (see java-proxy-agent.ts); set
 * while a proxy is advertised to the sandbox, undefined if the jar is not
 * shipped/found (JVMs then just aren't proxy-aware, as before).
 */
let javaAgentJarPath: string | undefined
// Per-session proxy auth token. Generated at proxy start, exported only into
// the sandbox child env, checked on every CONNECT/request — so a host process
// dialing 127.0.0.1:<proxyPort> can't reach the filter callback.
let proxyAuthToken: string | undefined
const sandboxViolationStore = new SandboxViolationStore()
// Per-session sentinel↔real-value map for masked credentials. Lives only in
// process memory; never written to disk or logged. Cleared on reset().
const sentinelRegistry = new SentinelRegistry()
// Per-session linked AWS credential pairs for SigV4 re-signing, keyed by
// the fake access key id. Same lifecycle and secrecy posture as the
// sentinel registry.
const awsPairRegistry = new AwsPairRegistry()
// Temp dir holding the sentinel-content fake files for masked credential
// files. Created lazily on first masked file; removed on reset().
const maskedFileStore = new MaskedFileStore()

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

function registerCleanup(): void {
  if (cleanupRegistered) {
    return
  }
  const cleanupHandler = () =>
    reset().catch(e => {
      logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
        level: 'error',
      })
    })
  process.once('exit', () => {
    void cleanupHandler()
    // On 'exit' reset() gets as far as its first await, so what it takes out
    // of the temp directory later than that goes here. After it, because on
    // Windows it starts by revoking a grant on the trust-bundle directory.
    // Only paths this process made and still holds: never a listing of the
    // temp directory, never a path out of the configuration.
    if (mitmCA) disposeMitmCASync(mitmCA)
    muxProxyServer?.removeBackendSocketSync()
    maskedFileStore.dispose()
  })
  process.once('SIGINT', cleanupHandler)
  process.once('SIGTERM', cleanupHandler)
  cleanupRegistered = true
}

/**
 * Attribution key to command text for every wrapped invocation, so each
 * producer can report (and ignoreViolations can match) the command an event
 * belongs to rather than the opaque key. Keys are held decoded because that
 * is the form the carriers deliver. Bounded FIFO: the violation store itself
 * only retains the last 100 events, so long-gone invocations need no entry.
 */
const MAX_COMMAND_TEXTS = 1024
const commandTextsByKey = new Map<string, string>()

/** Exported for testing. */
export function registerCommandText(
  command: string,
  options: WrapWithSandboxOptions | undefined,
): void {
  const key = decodeSandboxedCommand(
    encodeSandboxedCommand(attributionKeyFor(command, options?.commandId)),
  )
  const text = options?.commandText ?? command
  commandTextsByKey.delete(key)
  commandTextsByKey.set(key, text)
  while (commandTextsByKey.size > MAX_COMMAND_TEXTS) {
    const oldest = commandTextsByKey.keys().next().value
    if (oldest === undefined) break
    commandTextsByKey.delete(oldest)
  }
}

/**
 * The command text for a decoded attribution key. Keys arrive over carriers
 * the sandboxed process can write (the observe socket's event field, the
 * macOS log tag, the proxy username), so only a key this process registered
 * carries the embedder's own text; anything else is untrusted bytes.
 * Exported for testing.
 */
export function resolveCommandText(decodedKey: string): string {
  return (
    commandTextsByKey.get(decodedKey) ??
    sanitizeUnregisteredCommandKey(decodedKey)
  )
}

/**
 * The shortest commandId a per-command allow list may be registered under:
 * 16 random bytes (128 bits) as unpadded base64url. The floor only turns away
 * what is too short to hold 128 bits: it cannot tell a random id from a
 * predictable one of the same length.
 */
const MIN_NETWORK_LISTS_COMMAND_ID_LENGTH = 22

/**
 * Attribution key to the network allow list registered for one invocation
 * (registerCommandNetworkLists), keyed the way commandTextsByKey is because
 * the proxy username delivers both. The embedder removes an entry when its
 * command is gone. Not bounded the way commandTextsByKey is: dropping the
 * oldest entry would silently take a list away from a running command.
 */
const commandNetworkListsByKey = new Map<string, { allowedDomains: string[] }>()

function registerCommandNetworkLists(
  commandId: string,
  lists: { allowedDomains?: string[] },
): void {
  // The floor is measured on the key the map holds, not on the raw id, and
  // less U+FFFD: every unpaired surrogate becomes one, so it carries nothing.
  const key =
    typeof commandId === 'string'
      ? decodeSandboxedCommand(encodeSandboxedCommand(commandId))
      : ''
  // The id is not echoed in either message: it is what stands between a
  // sandboxed process and this list, and error text ends up in logs.
  if (key.replace(/\ufffd/g, '').length < MIN_NETWORK_LISTS_COMMAND_ID_LENGTH) {
    throw new Error(
      `registerCommandNetworkLists: commandId must be a string of at least ` +
        `${MIN_NETWORK_LISTS_COMMAND_ID_LENGTH} characters, unpaired ` +
        `surrogates not counted. The id is the ` +
        `only thing that binds a proxy connection to this allow list, and ` +
        `the sandboxed process chooses which id it presents, so it must be ` +
        `random (at least 128 bits, e.g. 16 random bytes as base64url) and ` +
        `never derived from the command text, a counter or the time.`,
    )
  }
  const allowedDomains = lists?.allowedDomains ?? []
  if (!Array.isArray(allowedDomains)) {
    throw new Error(
      'registerCommandNetworkLists: allowedDomains must be an array of strings.',
    )
  }
  for (const entry of allowedDomains) {
    if (typeof entry !== 'string' || !isValidAllowedDomainEntry(entry)) {
      throw new Error(
        `registerCommandNetworkLists: invalid allowedDomains entry ` +
          `${JSON.stringify(entry)}. ${ALLOWED_DOMAIN_ENTRY_MESSAGE}`,
      )
    }
  }
  commandNetworkListsByKey.set(
    key,
    // Copied, so the caller cannot change what was validated.
    { allowedDomains: [...allowedDomains] },
  )
  // An external HTTP proxy is handed no username, so no connection names an id.
  if (config?.network.httpProxyPort !== undefined) {
    logForDebugging(
      'registerCommandNetworkLists: network.httpProxyPort is set (an ' +
        'external proxy), so this list will never apply',
      { level: 'warn' },
    )
  }
}

function unregisterCommandNetworkLists(commandId: string): void {
  if (typeof commandId !== 'string') return
  commandNetworkListsByKey.delete(
    decodeSandboxedCommand(encodeSandboxedCommand(commandId)),
  )
}

/**
 * Record a proxy-side denial in the violation store so the model sees a
 * structured <sandbox_violations> block alongside the raw 403 / SOCKS
 * failure in stderr — parity with the macOS seatbelt log monitor and the
 * Linux seccomp observer. The proxy is the only component that knows the
 * destination host of a network deny, so neither of those can produce
 * this line. `encodedCommand` (from the proxy username) attributes it to
 * the invocation; without one the event is stored unattributed.
 */
function recordProxyViolation(
  line: string,
  encodedCommand: string | undefined,
): void {
  const command = encodedCommand
    ? resolveCommandText(decodeSandboxedCommand(encodedCommand))
    : undefined
  // Same suppression the seatbelt / seccomp monitors apply, so a
  // configured ignoreViolations pattern silences the event no matter
  // which producer saw it.
  if (shouldIgnoreViolation(line, command, config?.ignoreViolations)) {
    return
  }
  sandboxViolationStore.addViolation({
    line,
    encodedCommand,
    command,
    timestamp: new Date(),
  })
}

function recordOutboundDeny(
  host: string,
  port: number,
  reason: string,
  encodedCommand?: string,
): void {
  recordProxyViolation(
    `deny network-outbound ${host}:${port} (${reason})`,
    encodedCommand,
  )
}

/** Direct-dial `lookup` for the proxies: the current guard's, with a refusal recorded as a violation. */
const directLookup: DirectLookup =
  (port, encodedCommand) => (hostname, options, callback) =>
    resolvedAddressGuard.lookupFor(port)(
      hostname,
      options,
      (err, address, family) => {
        if (isResolvedAddressDenied(err)) {
          recordOutboundDeny(hostname, port, err.reason, encodedCommand)
        }
        callback(err, address, family)
      },
    )

/**
 * The request URL as it should appear in a model-visible violation line: as
 * spelled (parsed, a refused `/a/../b` would read `/b`), with a query string
 * or fragment reduced to a `?…` or `#…` marker. (The proxy rebuilds the
 * authority, so an embedded `name:pass@` is gone already.) Query strings
 * routinely carry credentials (api_key=, access_token=, signed URLs) that
 * the sandboxed client interpolated at runtime and that were never in the
 * model's context, so they must not enter the transcript via the
 * <sandbox_violations> block. The full URL still reaches the embedder's
 * filterRequest callback and its own debug logging.
 */
function redactUrlForViolation(url: string): string {
  const cut = url.search(/[?#]/)
  return cut === -1 ? url : `${url.slice(0, cut + 1)}…`
}

/** Whether an ask-callback answer is one of the two documented denials. */
function isDeclaredDenial(answer: unknown): boolean {
  return (
    answer === false ||
    (typeof answer === 'object' &&
      answer !== null &&
      (answer as { allow?: unknown }).allow === false)
  )
}

/**
 * The reason an ask-callback answer gives for denying, sanitized, or
 * undefined when it gives none that can be shown. Only
 * `{ allow: false, reason }` supplies one: a reason on any other object was
 * not written as the explanation of a denial.
 */
function denialReasonOf(answer: unknown): string | undefined {
  if (typeof answer !== 'object' || answer === null) return undefined
  const { allow, reason } = answer as { allow?: unknown; reason?: unknown }
  if (allow !== false || typeof reason !== 'string') return undefined
  return sanitizeDenialReason(reason) || undefined
}

/** Own keys only: an entry can be spelled `constructor`. */
function deniedDomainReason(entry: string): string {
  const reasons = config?.network.deniedDomainReasons ?? {}
  const own = Object.prototype.hasOwnProperty.call(reasons, entry)
  return (own ? reasons[entry] : undefined) ?? 'host is on the deny list'
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback: SandboxAskCallback | undefined,
  encodedCommand?: string,
  explain?: (reason: string) => void,
): Promise<boolean> {
  const denied = (reason: string): false => {
    recordOutboundDeny(host, port, reason, encodedCommand)
    explain?.(reason)
    return false
  }

  if (!config) {
    logForDebugging('No config available, denying network request')
    return denied('sandbox policy unavailable')
  }

  // Reject hosts containing control characters before pattern matching.
  // `matchesDomainPattern` uses string suffix matching which is trivially
  // fooled by e.g. `evil.com\x00.allowed.com` — the null byte passes
  // `.endsWith()` but truncates at the libc DNS layer. The SOCKS path is the
  // main exposure (DOMAINNAME is unvalidated bytes); HTTP is protected by
  // llhttp/URL parsing, but we check here for defence in depth.
  if (!isValidHost(host)) {
    logForDebugging(`Denying malformed host: ${JSON.stringify(host)}:${port}`, {
      level: 'error',
    })
    return denied('malformed host')
  }

  // Canonicalize so string comparisons match what getaddrinfo() will dial.
  // Without this, inet_aton shorthand like `2852039166` (= 169.254.169.254)
  // or `127.1` slips past a denylist entry for the dotted-decimal form.
  const canonicalHost = canonicalizeHost(host) ?? host

  // Check denied domains first
  for (const deniedDomain of config.network.deniedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, deniedDomain)) {
      logForDebugging(`Denied by config rule: ${host}:${port}`)
      // The matched entry's own reason when the caller supplied one, so the
      // model reads why this destination is off-limits (and the sanctioned
      // alternative) instead of a generic deny; keyed by the exact entry.
      return denied(deniedDomainReason(deniedDomain))
    }
  }

  // Check allowed domains
  for (const allowedDomain of config.network.allowedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging(`Allowed by config rule: ${host}:${port}`)
      return true
    }
  }

  // strictAllowlist makes the configured allowlist deterministic enforcement:
  // neither a per-command allow list nor the callback below can widen it.
  if (config.network.strictAllowlist) {
    logForDebugging(`No matching config rule, denying: ${host}:${port}`)
    return denied('host is not on the allow list')
  }

  // The allow list registered for the invocation the proxy username names.
  // Coming after both configured lists, it lifts the default deny for that
  // one command and never a configured deniedDomains entry. The username is
  // presented by the sandboxed client: see registerCommandNetworkLists.
  const perCommand = encodedCommand
    ? commandNetworkListsByKey.get(decodeSandboxedCommand(encodedCommand))
    : undefined
  for (const allowedDomain of perCommand?.allowedDomains ?? []) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging(`Allowed by per-command rule: ${host}:${port}`)
      return true
    }
  }

  if (!sandboxAskCallback) {
    logForDebugging(`No matching rule, denying: ${host}:${port}`)
    return denied('host is not on the allow list')
  }

  logForDebugging(`No matching rule, asking user: ${host}:${port}`)
  try {
    // Held as unknown: a JavaScript caller is not bound by the declared type.
    const answer: unknown = await sandboxAskCallback({ host, port })
    // Only `true` allows: an object is how a callback denies with a reason,
    // and a truthiness test here would read every such denial as an allow.
    if (answer === true) {
      logForDebugging(`User allowed: ${host}:${port}`)
      return true
    }
    if (!isDeclaredDenial(answer)) {
      logForDebugging(
        `Ask callback answered neither a boolean nor { allow: false, reason }; treating it as a denial: ${host}:${port}`,
        { level: 'warn' },
      )
    }
    logForDebugging(`User denied: ${host}:${port}`)
    // The callback's own reason, when it gave one, says what to do instead.
    return denied(denialReasonOf(answer) ?? 'user denied')
  } catch (error) {
    logForDebugging(`Error in permission callback: ${error}`, {
      level: 'error',
    })
    return denied('permission prompt failed')
  }
}

/**
 * Build the header-mutation callback that substitutes sentinel→real for
 * masked credentials. Returns undefined when no `credentials` block is
 * configured — wiring the seam at all is unnecessary then.
 *
 * Per-host gating happens inside the registry: each sentinel carries its
 * own injectHosts list and substitutes independently, so credential A's
 * sentinel cannot be laundered through credential B's allowed host. The
 * returned closure does not log header values; the registry holds the only
 * copy of the real value.
 */
function buildCredentialInjector(): MutateForwardedHeaders | undefined {
  if (!config?.credentials) return undefined
  return (headers, destHost) => {
    sentinelRegistry.substituteInHeaders(
      headers,
      destHost,
      matchesDomainPattern,
    )
  }
}

/**
 * Body counterpart of {@link buildCredentialInjector}: per-destination
 * sentinel→real pairs for streaming substitution in request bodies, with
 * the same per-credential injectHosts gating applied inside the registry.
 */
function buildBodyCredentialInjector(): GetBodySubstitutions | undefined {
  if (!config?.credentials) return undefined
  return destHost =>
    sentinelRegistry.sentinelsForHost(destHost, matchesDomainPattern)
}

/**
 * Build the per-request SigV4 hook for the TLS-terminating proxy.
 * Returns undefined when no `credentials` block is configured. The hook
 * consults {@link awsPairRegistry} at request time, so pairs registered
 * later (wrapWithSandbox runs after the proxy starts) are picked up.
 */
function buildSigv4Planner(): PlanSigv4 | undefined {
  if (!config?.credentials) return undefined
  // Re-read the policies per request (not captured at proxy start) so an
  // updateConfig() that changes credentials.sigv4 takes effect without a
  // proxy restart, matching how the injector sees live registry state.
  return (method, requestTarget, headers, destHost) =>
    createSigv4Planner(
      awsPairRegistry,
      config?.credentials?.sigv4,
      matchesDomainPattern,
    )(method, requestTarget, headers, destHost)
}

/**
 * Get the MITM proxy socket path for a given host, if configured.
 * Returns the socket path if the host matches any MITM domain pattern,
 * otherwise returns undefined.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) and the tlsTerminate exclusion below. This site
 * fails OPEN on a miss — a host that matches no MITM pattern is dialed
 * directly — so it must accept exactly the set of spellings the allowlist
 * accepts: otherwise `api.example.com.` (trailing-dot FQDN, same name to
 * DNS) passes the allowlist as `api.example.com` but misses every MITM
 * pattern and skips the MITM proxy entirely. The proxies already hand this
 * hook the canonical spelling; canonicalizing again here is defence in
 * depth for any other caller.
 */
function getMitmSocketPath(host: string): string | undefined {
  if (!config?.network.mitmProxy) {
    return undefined
  }

  const { socketPath, domains } = config.network.mitmProxy
  const canonicalHost = canonicalizeHost(host) ?? host

  for (const pattern of domains) {
    if (matchesDomainPattern(canonicalHost, pattern)) {
      logForDebugging(`Host ${host} matches MITM pattern ${pattern}`)
      return socketPath
    }
  }

  return undefined
}

/**
 * Per-host TLS-termination opt-out from network.tlsTerminate.excludeDomains.
 * Only consulted by the HTTP proxy when tlsTerminate is enabled; exempted
 * hosts fall back to the opaque CONNECT tunnel (still allowlist-filtered),
 * so mTLS / cert-pinning clients can complete their own handshake.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) — otherwise a spelling the allowlist accepts after
 * canonicalization (`127.1`, a trailing-dot FQDN) would dodge the exclusion
 * and get terminated anyway.
 */
function shouldTerminateTLSForHost(host: string): boolean {
  const excludeDomains = config?.network.tlsTerminate?.excludeDomains
  if (!excludeDomains?.length) return true
  const canonicalHost = canonicalizeHost(host) ?? host
  for (const pattern of excludeDomains) {
    if (!matchesDomainPattern(canonicalHost, pattern)) continue
    logForDebugging(
      `Host ${host} matches tlsTerminate.excludeDomains pattern ${pattern}; skipping TLS termination`,
    )
    // Masked-credential substitution only happens on the terminated path,
    // so a credential whose injectHosts cover this host can never be
    // injected here — the upstream gets the placeholder. Config validation
    // rejects the fully-contradictory spellings; this flags the partial
    // ones (e.g. default injectHosts = allowedDomains) at the moment they
    // actually bite.
    const masked = sentinelRegistry.namesInjectableAt(
      canonicalHost,
      matchesDomainPattern,
    )
    if (masked.length > 0) {
      logForDebugging(
        `tlsTerminate.excludeDomains: masked credential(s) ${masked.join(', ')} ` +
          `are configured for injection at ${host}, but its connections are ` +
          `not terminated, so the upstream will receive the placeholder`,
        { level: 'error' },
      )
    }
    return false
  }
  return true
}

async function startMuxProxyServer(
  sandboxAskCallback: SandboxAskCallback | undefined,
  portRange: readonly [number, number] | undefined,
): Promise<number> {
  const injectCredentials = buildCredentialInjector()
  const injectBodyCredentials = buildBodyCredentialInjector()
  httpProxyServer = createHttpProxyServer({
    filter: (port, host, _socket, encodedCommand, explain) =>
      filterNetworkRequest(
        port,
        host,
        sandboxAskCallback,
        encodedCommand,
        explain,
      ),
    getMitmSocketPath,
    mitmCA,
    shouldTerminateTLS: shouldTerminateTLSForHost,
    filterRequest: config?.network.filterRequest,
    plaintextHeaderSet: config?.network.allowPlaintextHeaderSet,
    stripResponseHeaders: config?.network.stripResponseHeaders,
    refuseOpaqueTunnels: config?.network.refuseOpaqueTunnels,
    requireHostMatch: config?.network.requireHostMatch,
    ambiguousRequestTarget: config?.network.ambiguousRequestTarget,
    // Read at each CONNECT, so that updateConfig changes them.
    get maxTerminatedTunnels() {
      return config?.network.tlsTerminate?.maxTunnels
    },
    get tlsHandshakeTimeoutMs() {
      return config?.network.tlsTerminate?.handshakeTimeoutMs
    },
    onFilterRequestDenied: ({ method, url, reason, encodedCommand }) => {
      // A refused CONNECT comes with its authority (`host:port`), not a URL.
      const target = method === 'CONNECT' ? url : redactUrlForViolation(url)
      recordProxyViolation(
        `deny http-request ${method} ${target} (${reason})`,
        encodedCommand,
      )
    },
    // TLS-terminated path always gets the injector; the plain-HTTP path
    // only when explicitly opted in. Without the opt-in, a sentinel sent
    // over plain HTTP reaches the upstream unchanged (fails closed).
    mutateHeaders: injectCredentials,
    mutateHeadersPlaintext: config?.credentials?.allowPlaintextInject
      ? injectCredentials
      : undefined,
    getBodySubstitutions: injectBodyCredentials,
    getBodySubstitutionsPlaintext: config?.credentials?.allowPlaintextInject
      ? injectBodyCredentials
      : undefined,
    // SigV4 re-signing is TLS-terminated-path only, like credential
    // injection: the real signature must not travel over plaintext.
    planSigv4: buildSigv4Planner(),
    parentProxy,
    lookupFor: directLookup,
    proxyAuthToken,
  })

  socksProxyServer = createSocksProxyServer({
    filter: (port, host, encodedCommand) =>
      filterNetworkRequest(port, host, sandboxAskCallback, encodedCommand),
    parentProxy,
    lookupFor: directLookup,
    proxyAuthToken,
    // A SOCKS tunnel is opaque, so the option that keeps opaque CONNECT
    // tunnels off the HTTP side must close this side of the port too.
    refuseOpaqueTunnels: config?.network.refuseOpaqueTunnels,
    onTunnelRefused: (port, host, encodedCommand) => {
      recordProxyViolation(
        `deny socks-tunnel ${host}:${port} (refuseOpaqueTunnels)`,
        encodedCommand,
      )
    },
    probeUnauthenticated: async (port, host) => {
      // Explicit deny rules only: an unauthenticated peer must never reach
      // the ask callback, and a merely off-list host gets the generic
      // cannot-authenticate refusal rather than a policy claim.
      if (!config) return {}
      const canonical = canonicalizeHost(host) ?? host
      for (const entry of config.network.deniedDomains) {
        if (matchesDomainPatternWithPort(canonical, port, entry)) {
          const reason = deniedDomainReason(entry)
          recordOutboundDeny(host, port, reason)
          return { deniedReason: reason }
        }
      }
      return {}
    },
  })

  muxProxyServer = createMuxProxyServer({
    httpServer: httpProxyServer,
    handleSocksConnection: s => socksProxyServer!.handleConnection(s),
    httpBackendPortRange: portRange,
  })

  const mux = muxProxyServer
  // Backend first so the front-end never accepts a connection that would
  // dispatch to an unbound backend. On Windows the backend's port is
  // excluded when binding the front-end in the same WFP range.
  const backendPort = await mux.listenHttpBackend()
  await listenInRange(
    mux.server,
    p => mux.server.listen(p, '127.0.0.1'),
    portRange,
    backendPort !== undefined ? new Set([backendPort]) : new Set(),
  )
  const muxPort = mux.getPort()
  if (muxPort === undefined) {
    throw new Error('Failed to get mux proxy server port')
  }
  mux.unref()
  logForDebugging(`Mux proxy (HTTP+SOCKS) listening on localhost:${muxPort}`)
  return muxPort
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

async function initialize(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
): Promise<void> {
  try {
    await initializeSteps(runtimeConfig, sandboxAskCallback, enableLogMonitor)
  } catch (error) {
    // Here, not at reset() or 'exit': a step can fail before the clean-up is
    // registered, and the next call makes a CA of its own.
    if (mitmCA) disposeMitmCASync(mitmCA)
    mitmCA = undefined
    throw error
  }
}

async function initializeSteps(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback: SandboxAskCallback | undefined,
  enableLogMonitor: boolean,
): Promise<void> {
  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    activateLandstripSession()
    return
  }

  assertLandstripConfig(runtimeConfig, enableLogMonitor)
  const portRange = landstripProxyPortRange()
  if (
    portRange &&
    [
      runtimeConfig.network.httpProxyPort,
      runtimeConfig.network.socksProxyPort,
    ].some(
      port =>
        port !== undefined && (port < portRange[0] || port > portRange[1]),
    )
  ) {
    throw new Error(
      'External proxy ports must be inside the Landstrip Windows firewall range',
    )
  }
  // Store config for use by other functions
  config = runtimeConfig

  // Resolve parent/upstream proxy from config or HTTP_PROXY env before we
  // start our own listeners (which will later shadow those vars in the child).
  parentProxy = resolveParentProxy(runtimeConfig.network.parentProxy)
  if (parentProxy) {
    logForDebugging(
      `Parent proxy configured: http=${redactUrl(parentProxy.httpUrl)} ` +
        `https=${redactUrl(parentProxy.httpsUrl)}`,
    )
  }
  resolvedAddressGuard = createResolvedAddressGuard(runtimeConfig.network)

  // Load TLS-termination CA if configured. Throws on unreadable/non-PEM —
  // tlsTerminate is explicit opt-in, so a bad config is a hard error.
  if (runtimeConfig.network.tlsTerminate && runtimeConfig.network.mitmProxy) {
    throw new Error(
      'network.tlsTerminate and network.mitmProxy are mutually exclusive',
    )
  }
  // Before any CA, proxy or sandbox is set up: a runtime that cannot
  // terminate TLS in-process fails here, not on each tunnel.
  if (runtimeConfig.network.tlsTerminate) assertTlsTerminationSupported()
  mitmCA = runtimeConfig.network.tlsTerminate
    ? createMitmCA(runtimeConfig.network.tlsTerminate)
    : undefined

  // Check dependencies
  const deps = await checkDependenciesAsync()
  if (deps.errors.length > 0) {
    throw new Error(
      `Sandbox dependencies not available: ${deps.errors.join(', ')}`,
    )
  }

  registerCleanup()

  if (enableLogMonitor && getPlatform() === 'macos') {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      config.ignoreViolations,
      resolveCommandText,
    )
    logForDebugging('Started macOS sandbox log monitor')
  }

  // Initialize network infrastructure
  initializationPromise = (async () => {
    try {
      // The auth token is only set when this process owns the proxy; an
      // external proxy (config.network.httpProxyPort) handles its own auth,
      // and embedding our token in its URL would be wrong.
      proxyAuthToken =
        config.network.httpProxyPort !== undefined
          ? undefined
          : randomBytes(16).toString('hex')

      // The mux front-end serves both protocols on one port. Each side's
      // reported port is the external override if configured, else the mux
      // port — so the public config.network.{http,socks}ProxyPort contract
      // is unchanged. The mux is skipped only when BOTH are external.
      const needLocalProxy =
        config.network.httpProxyPort === undefined ||
        config.network.socksProxyPort === undefined
      const muxPort = needLocalProxy
        ? await startMuxProxyServer(sandboxAskCallback, portRange)
        : undefined
      const httpProxyPort = config.network.httpProxyPort ?? muxPort!
      const socksProxyPort = config.network.socksProxyPort ?? muxPort!
      // JVMs read neither HTTPS_PROXY nor its credential; the agent bridges
      // both. Resolved once here, advertised via JAVA_TOOL_OPTIONS per command.
      // Async: the global-npm fallback spawns `npm root -g`.
      javaAgentJarPath =
        (await getJavaProxyAgentJarPathAsync(config.javaAgentJarPath)) ??
        undefined
      // Leaves are minted lazily per-CONNECT (after this point), so setting
      // the CDP URL now means every leaf carries it. See MitmCA.crlUrl.
      // Schannel clients fetch revocation data from this host-local listener.
      if (mitmCA && muxPort !== undefined && getPlatform() === 'windows') {
        mitmCA.crlUrl = `http://127.0.0.1:${muxPort}${CRL_PATH}`
      }
      if (config.network.httpProxyPort !== undefined) {
        logForDebugging(`Using external HTTP proxy on port ${httpProxyPort}`)
      }
      if (config.network.socksProxyPort !== undefined) {
        logForDebugging(`Using external SOCKS proxy on port ${socksProxyPort}`)
      }

      const context: HostNetworkManagerContext = {
        httpProxyPort,
        socksProxyPort,
      }
      managerContext = context
      logForDebugging('Network infrastructure initialized')
      return context
    } catch (error) {
      // Clear state on error so initialization can be retried
      initializationPromise = undefined
      managerContext = undefined
      reset().catch(e => {
        logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
          level: 'error',
        })
      })
      throw error
    }
  })()

  await initializationPromise
  activateLandstripSession()
}

function isSupportedPlatform(): boolean {
  const platform = getPlatform()
  if (platform === 'linux') {
    // WSL1 does not provide the Linux sandboxing primitives.
    return getWslVersion() !== '1'
  }
  return platform === 'macos' || platform === 'windows'
}

function isSandboxingEnabled(): boolean {
  // Sandboxing is enabled if config has been set (via initialize())
  return config !== undefined
}

/**
 * Platform-independent part of the dependency check. Returns either
 * a finished result (POSIX, unsupported platform, or a Windows
 * srt-win resolution failure) or the inputs for the Windows probe —
 * the only platform where the sync and async variants differ.
 */
function checkDependencies(
  _ripgrepConfig?: RipgrepConfig,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []
  if (!isSupportedPlatform()) {
    errors.push('Unsupported platform')
  } else {
    const reason = landstripUnavailableReason()
    if (reason !== undefined) errors.push(reason)
  }
  if (!config?.filesystem.disabled) {
    try {
      const warning = ownInstallWarning(writeRootsOf(getFsWriteConfig()))
      if (warning !== undefined) warnings.push(warning)
    } catch {
      // It only advises: whoever enforces a config says what is wrong with it.
    }
  }
  return { errors, warnings }
}

/** Check the installed Landstrip binary; no legacy tools are required. */
async function checkDependenciesAsync(
  ripgrepConfig?: RipgrepConfig,
): Promise<SandboxDependencyCheck> {
  return checkDependencies(ripgrepConfig)
}

/**
 * Build the read-deny / env-unset / env-set maps implied by the
 * `credentials` config.
 *
 * Only explicitly declared sources are restricted: `mode: 'deny'` file
 * entries join the read-deny set, `mode: 'deny'` env vars are unset, and
 * `mode: 'mask'` env vars are set to a fake value (whole-value sentinel,
 * the real value with extract-captured spans swapped for sentinels, or a
 * JWT-shaped fake for `decode: 'jwt'` / `maskClaims` entries) registered
 * in {@link sentinelRegistry} — see {@link buildMaskedEnvVars}.
 */
function getCredentialRestrictions(
  credentials: CredentialsConfig | undefined,
  allowedDomains: readonly string[] | undefined,
): CredentialRestrictionConfig {
  if (!credentials) {
    return {
      denyReadPaths: [],
      unsetEnvVars: [],
      setEnvVars: {},
      maskedFileBinds: [],
      maskedFileStoreDir: undefined,
      degradeToDenyPaths: [],
    }
  }

  const denyReadPaths = getCredentialDenyReadPaths(credentials)

  // Default injectHosts (= allowedDomains) is host-scoped: drop any
  // `:port` suffixes, otherwise the sentinel would carry an entry no bare
  // destination host can ever match and the credential would never inject.
  const defaultInjectHosts = [
    ...new Set((allowedDomains ?? []).map(stripDomainPatternPort)),
  ]

  const unsetEnvVars: string[] = []
  for (const v of credentials.envVars ?? []) {
    if (v.mode === 'deny') unsetEnvVars.push(v.name)
  }

  // Masked env vars: read the real value from the host environment,
  // register sentinel(s), and set the variable to the fake value inside
  // the sandbox. degradeToUnsetNames carries variables whose extract
  // pattern matched nothing with onExtractNoMatch: "deny" — merged into
  // unsetEnvVars below so the value is withheld rather than exposed.
  const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
    credentials.envVars ?? [],
    defaultInjectHosts,
    sentinelRegistry,
  )
  unsetEnvVars.push(...degradeToUnsetNames)

  // Link masked AWS credentials into pairs so the proxy can re-sign
  // SigV4 requests (the signature is derived from the secret; header
  // substitution alone cannot fix it).
  registerAwsPairs(
    credentials.envVars ?? [],
    credentials.awsPairs,
    defaultInjectHosts,
    setEnvVars,
    awsPairRegistry,
  )

  // Masked files: read the real bytes on the host, register a sentinel,
  // write it to a fake file in the manager-owned temp dir. Missing/unreadable
  // entries are skipped (same posture as an unset masked env var).
  // degradeToDenyPaths carries paths whose extract pattern matched
  // nothing with onExtractNoMatch: "deny" — merged into denyReadPaths
  // below so both the read-deny config and the platform builders see
  // them, and carried separately so they stay literal on the way there.
  const files = credentials.files ?? []
  const { binds: maskedFileBinds, degradeToDenyPaths } = buildMaskedFileBinds(
    files,
    defaultInjectHosts,
    sentinelRegistry,
    maskedFileStore,
  )

  return {
    denyReadPaths,
    unsetEnvVars: [...new Set(unsetEnvVars)],
    setEnvVars,
    maskedFileBinds,
    maskedFileStoreDir: maskedFileStore.dirPath,
    degradeToDenyPaths,
  }
}

/**
 * Pure (side-effect-free) chokepoint for credential file-deny
 * paths — `credentials.files` entries with `mode: 'deny'`. Any
 * code that needs the credential→denyRead contribution routes
 * through here so a comparison predicate can read it without
 * touching {@link sentinelRegistry}.
 */
function getCredentialDenyReadPaths(
  credentials: CredentialsConfig | undefined,
): string[] {
  const files = credentials?.files ?? []
  return [...new Set(files.filter(f => f.mode === 'deny').map(f => f.path))]
}

/**
 * The default write paths under a filesystem policy's read rules, for
 * getFsWriteConfig() and wrapWithSandbox() alike. Fed the entries as
 * configured, through the pure {@link getCredentialDenyReadPaths}: no glob
 * expansion and no credential masking, because getFsWriteConfig() is a
 * getter callers reach from permission checks and render paths. A mask entry
 * that degrades to a deny is a file and cannot cover a directory, so
 * leaving those out changes nothing. An entry with glob characters that is
 * also the name of a path counts as that name too. The credential denies are
 * judged apart, with no `allowRead`: they have no exceptions.
 */
function defaultWritePathsUnder({
  denyRead,
  allowRead,
  credentials,
}: {
  denyRead: readonly FilesystemPathEntry[]
  allowRead: readonly FilesystemPathEntry[] | undefined
  credentials: CredentialsConfig | undefined
}): string[] {
  if (getPlatform() === 'windows') return []
  const underCredentialDenies = getDefaultWritePaths(
    readRulesOf([], undefined, getCredentialDenyReadPaths(credentials)),
  )
  return getDefaultWritePaths(readRulesOf(denyRead, allowRead, [])).filter(p =>
    underCredentialDenies.includes(p),
  )
}

/** Inspect the native patterns passed to Landstrip, without host-side expansion. */
function getFsReadConfig(): FsReadRestrictionConfig {
  if (!config || config.filesystem.disabled) {
    return { denyOnly: [], allowWithinDeny: [] }
  }
  const credentialDenyOnly = getCredentialDenyReadPaths(config.credentials)
  return {
    denyOnly: [...spelledOf(config.filesystem.denyRead), ...credentialDenyOnly],
    allowWithinDeny: spelledOf(config.filesystem.allowRead ?? []),
    credentialDenyOnly,
    ...literalReadLists(
      config.filesystem.denyRead,
      config.filesystem.allowRead,
    ),
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  if (!config) {
    return { allowOnly: getDefaultWritePaths(), denyWithinAllow: [] }
  }

  if (config.filesystem.disabled) {
    return { allowOnly: ['/'], denyWithinAllow: [] }
  }

  const allowPaths = spelledOf(config.filesystem.allowWrite)
  const denyPaths = spelledOf(config.filesystem.denyWrite)

  const allowOnly = [
    ...defaultWritePathsUnder({
      denyRead: config.filesystem.denyRead,
      allowRead: config.filesystem.allowRead,
      credentials: config.credentials,
    }),
    ...allowPaths,
  ]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
    ...literalWriteLists(
      config.filesystem.allowWrite,
      config.filesystem.denyWrite,
    ),
  }
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  if (!config) {
    return {}
  }

  // Preserve an explicitly-empty allowlist: consumers need to distinguish
  // "no network restriction configured" (absent) from "allowlist configured
  // with zero entries" (block-all / ask-only). Stripping the empty array
  // made a host app's restriction-status UI report an airgapped config as
  // unrestricted. deniedHosts keeps the strip — an empty denylist and an
  // absent one are semantically identical.
  const allowedHosts = config.network.allowedDomains
  const deniedHosts = config.network.deniedDomains

  return {
    allowedHosts,
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  return config?.network?.allowUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  return config?.network?.allowLocalBinding
}

function getAllowMachLookup(): string[] | undefined {
  return config?.network?.allowMachLookup
}

function getIgnoreViolations(): Record<string, string[]> | undefined {
  return config?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  return config?.enableWeakerNestedSandbox
}

/**
 * Union of session-level and per-call `git.safeDirectories`. Marks
 * paths as `safe.directory` (dubious-ownership bypass) WITHOUT
 * touching the write grant — the repo top-level for a subdirectory
 * launch must NOT go in `filesystem.allowWrite`.
 */
function getGitSafeDirectories(
  customConfig?: Partial<SandboxRuntimeConfig>,
): string[] {
  return [
    ...(config?.git?.safeDirectories ?? []),
    ...(customConfig?.git?.safeDirectories ?? []),
  ]
}

function getProxyAuthToken(): string | undefined {
  return proxyAuthToken
}

function getProxyPort(): number | undefined {
  return managerContext?.httpProxyPort
}

function getSocksProxyPort(): number | undefined {
  return managerContext?.socksProxyPort
}

function getLinuxHttpSocketPath(): string | undefined {
  return undefined
}

function getLinuxSocksSocketPath(): string | undefined {
  return undefined
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
async function waitForNetworkInitialization(): Promise<boolean> {
  if (!config) {
    return false
  }
  if (initializationPromise) {
    try {
      await initializationPromise
      return true
    } catch {
      return false
    }
  }
  return managerContext !== undefined
}

/**
 * Per-invocation options for {@link wrapWithSandbox} /
 * {@link wrapWithSandboxArgv} that aren't sandbox *policy* (that's
 * `customConfig`).
 */
export type WrapWithSandboxOptions = {
  /**
   * Opaque per-invocation correlation key. Violations observed while the
   * wrapped command runs (seatbelt log lines, seccomp events, proxy denies)
   * are stored under this key, so it must equal what you later pass to
   * `annotateStderrWithSandboxFailures` / `getViolationsForCommand`.
   * Defaults to `command`. Prefer a unique id (e.g. a tool-use id) over the
   * command text: keys are compared on their first 100 characters, so two
   * long commands sharing a prefix would otherwise cross-attribute, and a
   * rerun of the same text would inherit the earlier run's events.
   *
   * An id that a network allow list is registered under must also be
   * unguessable: see `registerCommandNetworkLists`.
   */
  commandId?: string
  /**
   * The command this invocation *represents*, when that differs from the
   * string being wrapped (e.g. you wrap an assembled
   * `source <snapshot> && eval '<cmd>'` but the user-facing command is
   * `<cmd>`). Used for `ignoreViolations` command-pattern matching and
   * reported as the violation's `command`. Defaults to `command`.
   */
  commandText?: string
}

async function wrapWithSandbox(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  options?: WrapWithSandboxOptions,
  cwd?: string,
): Promise<string> {
  if (getPlatform() === 'windows') {
    throw new Error(
      'wrapWithSandbox() is not supported on Windows; use wrapWithSandboxArgv() with {shell: false}',
    )
  }
  return quoteLandstripInvocation(
    await wrapWithSandboxArgv(
      command,
      binShell,
      customConfig,
      abortSignal,
      cwd,
      options,
    ),
  )
}

/** Return a native Landstrip invocation. Always spawn with {shell: false}. */
async function wrapWithSandboxArgv(
  command: string,
  binShell?: string | WindowsBinShell,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  cwd?: string,
  options?: WrapWithSandboxOptions,
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
  abortSignal?.throwIfAborted()
  const pending = initializationPromise
  if (pending) await pending
  if (pending !== initializationPromise) {
    throw new Error('Sandbox was reset while wrapping the command')
  }
  abortSignal?.throwIfAborted()
  const state = beginLandstripWrap(config, customConfig)
  const effective = state.config
  const fsDisabled = effective.filesystem.disabled
  const credentials = getCredentialRestrictions(
    effective.credentials,
    effective.network.allowedDomains,
  )
  const needsNetworkRestriction = effective.network.allowedDomains !== undefined
  registerCommandText(command, options)
  const ownAllowWithinDeny = [
    ...(mitmCA
      ? [
          mitmCA.certPath,
          mitmCA.trustBundlePath,
          ...(getPlatform() === 'windows'
            ? [dirname(mitmCA.trustBundlePath)]
            : []),
        ]
      : []),
    ...(javaAgentJarPath ? [javaAgentJarPath] : []),
  ]
  const writeConfig: FsWriteRestrictionConfig | undefined = fsDisabled
    ? undefined
    : {
        allowOnly: [
          ...defaultWritePathsUnder({
            denyRead: effective.filesystem.denyRead,
            allowRead: effective.filesystem.allowRead,
            credentials: effective.credentials,
          }),
          ...spelledOf(effective.filesystem.allowWrite),
        ],
        denyWithinAllow: spelledOf(effective.filesystem.denyWrite),
        ...literalWriteLists(
          effective.filesystem.allowWrite,
          effective.filesystem.denyWrite,
        ),
      }
  if (writeConfig && !ownInstallLogged) {
    ownInstallLogged = true
    try {
      const ownInstall = ownInstallWarning(writeRootsOf(writeConfig))
      if (ownInstall !== undefined) {
        logForDebugging(ownInstall, { level: 'warn' })
      }
    } catch {
      // It only advises, as in checkDependencies().
    }
  }
  return wrapWithLandstrip(state, {
    command,
    commandId: options?.commandId,
    platform: getPlatform(),
    logTag:
      getPlatform() === 'macos'
        ? generateLogTag(options?.commandId ?? command)
        : undefined,
    cwd: cwd ?? process.cwd(),
    binShell,
    needsNetworkRestriction,
    httpProxyPort: needsNetworkRestriction ? getProxyPort() : undefined,
    socksProxyPort: needsNetworkRestriction ? getSocksProxyPort() : undefined,
    proxyAuthToken: needsNetworkRestriction ? proxyAuthToken : undefined,
    caCertPath: mitmCA?.trustBundlePath,
    javaAgentJarPath: needsNetworkRestriction ? javaAgentJarPath : undefined,
    readConfig: fsDisabled
      ? undefined
      : {
          denyOnly: [
            ...spelledOf(effective.filesystem.denyRead),
            ...credentials.denyReadPaths,
          ],
          credentialDenyOnly: credentials.denyReadPaths,
          allowWithinDeny: spelledOf(effective.filesystem.allowRead ?? []),
          ownAllowWithinDeny,
          ...literalReadLists(
            effective.filesystem.denyRead,
            effective.filesystem.allowRead,
          ),
        },
    writeConfig,
    maskedFileBinds: credentials.maskedFileBinds,
    degradeToDenyPaths: credentials.degradeToDenyPaths,
    unsetEnvVars: credentials.unsetEnvVars,
    setEnvVars: credentials.setEnvVars,
    gitSafeDirectories: getGitSafeDirectories(customConfig),
  })
}

/**
 * Get the current sandbox configuration
 * @returns The current configuration, or undefined if not initialized
 */
function getConfig(): SandboxRuntimeConfig | undefined {
  return config
}

/**
 * Update the sandbox configuration in place.
 *
 * **Network/allowlist changes are a live swap**: the running
 * mux proxy reads `config.network.allowedDomains` /
 * `deniedDomains` per-request (via `filterNetworkRequest`), so
 * reassigning `config` here takes effect on the next connection
 * with no proxy rebind and no port change — on every platform,
 * including Windows. This is what lets a host enable/deny domains
 * for already-running sandboxed children.
 *
 * Filesystem changes (denyRead/denyWrite) are NOT applied live:
 * macOS bakes them into the seatbelt profile at wrap time, and
 * Linux/Windows bake them into the bwrap argv / DENY-ACE set at
 * wrap time. Call reset() + initialize() to apply a new
 * filesystem config.
 *
 * @param newConfig - The new configuration to use
 */
function updateConfig(newConfig: SandboxRuntimeConfig): void {
  assertLandstripConfig(newConfig)
  // Built before anything is swapped, so a malformed range leaves the
  // previous config fully in effect.
  const nextGuard = createResolvedAddressGuard(newConfig.network)
  // Deep clone the config to avoid mutations. structuredClone cannot clone
  // functions, so pull filterRequest out, clone the rest, and put it back —
  // a function reference is immutable in the sense that matters here.
  const { filterRequest, ...rest } = newConfig.network
  config = structuredClone({ ...newConfig, network: rest })
  config.network.filterRequest = filterRequest
  resolvedAddressGuard = nextGuard
  // Re-resolve parent proxy so hot-reload picks up changes. Note: the proxy
  // servers capture `parentProxy` by value at creation, so changes here take
  // effect only on re-initialize. This keeps the state consistent for the
  // next initialize() call.
  parentProxy = resolveParentProxy(newConfig.network.parentProxy)
  logForDebugging('Sandbox configuration updated')
}

/** Kept for API compatibility; Landstrip creates no host bind-mount placeholders. */
function cleanupAfterCommand(): void {}

/**
 * Forcibly close an http.Server, including any in-flight requests.
 *
 * Plain `server.close()` waits for every active request to finish.
 * The proxy may be mid-upstream-request when reset() runs (e.g. a test's
 * curl was killed by --max-time while the proxy was still dialing the
 * real example.com / api.github.com), and `dialDirect()` allows up to
 * 30s before giving up. Combined with a socat fork that hasn't yet seen
 * its unix-socket EOF, that leaves a fully-open inbound connection and
 * `server.close()` never calls back. `closeAllConnections()` (Node 18.2+,
 * also implemented in Bun) tears down those sockets so `close()` resolves
 * immediately.
 */
function forceCloseHttpServer(
  server: ReturnType<typeof createHttpProxyServer>,
): Promise<void> {
  return new Promise<void>(resolve => {
    // Must run *before* close(): in Bun, close() also detaches the
    // underlying handle, so a closeAllConnections() called afterwards
    // becomes a no-op and the close callback waits for the in-flight
    // request to drain — defeating the purpose. With closeAllConnections()
    // first, the connections are gone by the time close() runs and its
    // callback fires immediately (Bun reports "Server is not running.",
    // Node reports no error). Verified against both orderings.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections()
    }
    server.close(error => {
      if (error && error.message !== 'Server is not running.') {
        logForDebugging(`Error closing HTTP proxy server: ${error.message}`, {
          level: 'error',
        })
      }
      resolve()
    })
  })
}

async function reset(): Promise<void> {
  beginLandstripReset()
  config = undefined
  ownInstallLogged = false
  if (logMonitorShutdown) {
    logMonitorShutdown()
    logMonitorShutdown = undefined
  }

  // Close servers in parallel (only if they exist, i.e., were started by us)
  const closePromises: Promise<void>[] = []

  if (mitmCA) {
    closePromises.push(disposeMitmCA(mitmCA))
  }

  if (muxProxyServer) {
    closePromises.push(
      muxProxyServer.close().catch((error: Error) => {
        logForDebugging(`Error closing mux proxy server: ${error.message}`, {
          level: 'error',
        })
      }),
    )
  }

  if (httpProxyServer) {
    closePromises.push(forceCloseHttpServer(httpProxyServer))
  }

  if (socksProxyServer) {
    const socksClose = socksProxyServer.close().catch((error: Error) => {
      logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
        level: 'error',
      })
    })
    closePromises.push(socksClose)
  }

  // Wait for all servers to close
  await Promise.all(closePromises)

  // Clear references
  muxProxyServer = undefined
  httpProxyServer = undefined
  proxyAuthToken = undefined
  socksProxyServer = undefined
  managerContext = undefined
  initializationPromise = undefined
  parentProxy = undefined
  resolvedAddressGuard = createResolvedAddressGuard()
  mitmCA = undefined
  javaAgentJarPath = undefined
  sentinelRegistry.clear()
  awsPairRegistry.clear()
  commandTextsByKey.clear()
  commandNetworkListsByKey.clear()
  maskedFileStore.dispose()
}

function getSandboxViolationStore() {
  return sandboxViolationStore
}

function annotateStderrWithSandboxFailures(
  command: string,
  stderr: string,
): string {
  if (!config) {
    return stderr
  }

  const violations = sandboxViolationStore.getViolationsForCommand(command)
  if (violations.length === 0) {
    return stderr
  }

  let annotated = stderr
  annotated += EOL + '<sandbox_violations>' + EOL
  for (const violation of violations) {
    annotated += violation.line + EOL
  }
  annotated += '</sandbox_violations>'

  return annotated
}

/**
 * Returns glob patterns from Edit/Read permission rules that are not
 * fully supported on Linux. Returns empty array on macOS or when
 * sandboxing is disabled.
 *
 * Patterns ending with /** are excluded since they work as subpaths.
 * So are entries marked literal. An entry that is also the name of a path
 * that exists is still returned: what is returned must not depend on what
 * is on the disk, which a sandboxed command can change.
 */
function getLinuxGlobPatternWarnings(): string[] {
  return []
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
  initialize(
    runtimeConfig: SandboxRuntimeConfig,
    sandboxAskCallback?: SandboxAskCallback,
    enableLogMonitor?: boolean,
  ): Promise<void>
  isSupportedPlatform(): boolean
  isSandboxingEnabled(): boolean
  checkDependencies(ripgrepConfig?: {
    command: string
    args?: string[]
  }): SandboxDependencyCheck
  checkDependenciesAsync(ripgrepConfig?: {
    command: string
    args?: string[]
  }): Promise<SandboxDependencyCheck>
  getFsReadConfig(): FsReadRestrictionConfig
  getFsWriteConfig(): FsWriteRestrictionConfig
  getNetworkRestrictionConfig(): NetworkRestrictionConfig
  getAllowUnixSockets(): string[] | undefined
  getAllowLocalBinding(): boolean | undefined
  getAllowMachLookup(): string[] | undefined
  getIgnoreViolations(): Record<string, string[]> | undefined
  getEnableWeakerNestedSandbox(): boolean | undefined
  getProxyPort(): number | undefined
  getProxyAuthToken(): string | undefined
  getSocksProxyPort(): number | undefined
  getLinuxHttpSocketPath(): string | undefined
  getLinuxSocksSocketPath(): string | undefined
  waitForNetworkInitialization(): Promise<boolean>
  wrapWithSandbox(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
    options?: WrapWithSandboxOptions,
  ): Promise<string>
  wrapWithSandboxArgv(
    command: string,
    binShell?: string | WindowsBinShell,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
    cwd?: string,
    options?: WrapWithSandboxOptions,
  ): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }>
  /**
   * Register the network allow list of one invocation, under the `commandId`
   * its wrap was given ({@link WrapWithSandboxOptions}). Entries are matched
   * and validated as `network.allowedDomains` entries are; an invalid one
   * throws. Registering an id again replaces its list.
   *
   * Order of evaluation for a connection: a configured `deniedDomains` match
   * denies; a configured `allowedDomains` match allows;
   * `network.strictAllowlist` denies; a match in the list registered for the
   * id the connection presents allows; then the ask callback decides if
   * there is one, and otherwise the connection is denied. So a per-command
   * entry never overrides a configured `deniedDomains` entry and is ignored
   * entirely under `strictAllowlist`. It also never enters `network.*`, so
   * the default `injectHosts` scope of a masked credential does not grow.
   *
   * The proxy reads the id from the proxy username, which the sandboxed
   * client presents, so the id is the ONLY thing binding a connection to an
   * allow list. It MUST be unguessable: at least 128 bits of randomness (16
   * random bytes as base64url, 22 characters; a shorter id throws), never a
   * counter, a timestamp or anything derived from the command. Presenting
   * another live invocation's id gets that invocation's allows: this is
   * attribution, not a boundary between concurrent commands of one session.
   *
   * Register just before spawning the wrapped command, and unregister when
   * the child exits or never started: a registration that outlives its
   * command widens the window in which its id is worth presenting.
   *
   * As with every attribution key, only the first 100 characters of an id
   * take part, and a list under an id whose encoded form does not fit in the
   * proxy username (possible only with non-ASCII ids) never applies. An
   * unpaired surrogate does not count towards the 22 characters.
   *
   * No list applies while `network.httpProxyPort` names an external proxy:
   * the wrap gives that proxy no username, so no connection carries an id.
   * Registering still succeeds, and every connection is decided as if no list
   * existed.
   */
  registerCommandNetworkLists(
    commandId: string,
    lists: { allowedDomains?: string[] },
  ): void
  /**
   * Remove the list registered for `commandId`. A no-op for an id that has
   * none. `reset()` removes them all.
   */
  unregisterCommandNetworkLists(commandId: string): void
  /**
   * True when the network filter understands an ask callback's
   * `{ allow: false, reason }` answer (see {@link SandboxAskCallback}). Read
   * it before returning that object: releases up to v0.0.77 allow on any
   * truthy answer, so there the object would be read as an allow. Where this
   * is absent, deny with a plain `false`.
   */
  readonly askCallbackDenyReason: true
  getSandboxViolationStore(): SandboxViolationStore
  annotateStderrWithSandboxFailures(command: string, stderr: string): string
  getLinuxGlobPatternWarnings(): string[]
  getConfig(): SandboxRuntimeConfig | undefined
  getMitmCA(): MitmCA | undefined
  getSentinelRegistry(): SentinelRegistry
  getAwsPairRegistry(): AwsPairRegistry
  getMaskedFileStore(): MaskedFileStore
  updateConfig(newConfig: SandboxRuntimeConfig): void
  cleanupAfterCommand(): void
  reset(): Promise<void>
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  checkDependenciesAsync,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getProxyAuthToken,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  registerCommandNetworkLists,
  unregisterCommandNetworkLists,
  askCallbackDenyReason: true,
  cleanupAfterCommand,
  reset,
  getMitmCA: () => mitmCA,
  getSentinelRegistry: () => sentinelRegistry,
  getAwsPairRegistry: () => awsPairRegistry,
  getMaskedFileStore: () => maskedFileStore,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
