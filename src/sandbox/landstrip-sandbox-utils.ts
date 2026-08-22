import { spawnSync } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  resolve,
  win32,
} from 'node:path'
import {
  binaryPath,
  type LandstripPathSelector,
  type LandstripPolicy,
} from '@landstrip/landstrip-api'
import type * as LandstripShared from '@landstrip/landstrip-api/lib/shared'
import { getPlatform, type Platform } from '../utils/platform.js'
import { realPathOf, wayTo } from '../utils/real-path.js'
import { quote } from '../utils/shell-quote.js'
import { whichSync } from '../utils/which.js'
import { GlobTokenKind, parseGlob, type GlobToken } from './glob-pattern.js'
import { buildJavaToolOptions } from './java-proxy-agent.js'
import {
  literalReadings,
  type PathListKind,
  type PathReading,
} from './path-entries.js'
import type { SandboxRuntimeConfig } from './sandbox-config.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import {
  buildPosixGitSafeDirEnv,
  collapseInteriorSpellings,
  containsGlobCharsForPlatform,
  DANGEROUS_FILES,
  encodeSandboxedCommand,
  expandTilde,
  expandWindowsEnvRefs,
  generateProxyEnvVars,
  getDangerousDirectories,
  isAtOrUnder,
  isUncPath,
  nameLocation,
  removeTrailingGlobSuffix,
  stripExtendedPathPrefix,
  toForwardSlashes,
} from './sandbox-utils.js'
import {
  parseWindowsBinShell,
  type WindowsBinShell,
} from './windows-sandbox-utils.js'

const {
  buildLandstripPolicy: buildSharedLandstripPolicy,
  matchesPathPattern,
  mergeArray,
  pathUnderDirectory,
  serializeLandstripPolicy,
} = createRequire(import.meta.url)(
  '@landstrip/landstrip-api/shared',
) as typeof LandstripShared
type LandstripPlatform = Exclude<Platform, 'unknown'>

export interface LandstripShell {
  exe: string
  args: readonly string[]
}

export interface BuildLandstripPolicyOptions {
  platform?: LandstripPlatform
  cwd: string
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  allowLocalBinding?: boolean
  allowUnixSockets?: readonly string[]
  allowAllUnixSockets?: boolean
  enableWeakerNetworkIsolation?: boolean
  allowMachLookup?: readonly string[]
  allowAppleEvents?: boolean
  allowPty?: boolean
  logTag?: string
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  mandatoryDenyWrite?: readonly LandstripPathSelector[]
  maskedFileBinds?: ReadonlyArray<{ realPath: string; fakePath: string }>
  degradeToDenyPaths?: readonly string[]
}

export interface WrapCommandWithLandstripOptions
  extends BuildLandstripPolicyOptions {
  platform: LandstripPlatform
  shell: LandstripShell
  landstripPath?: string
  command: string
  commandId?: string
  proxyAuthToken?: string
  caCertPath?: string
  javaAgentJarPath?: string
  unsetEnvVars?: readonly string[]
  setEnvVars?: Readonly<Record<string, string>>
  gitSafeDirectories?: readonly string[]
}

export interface LandstripInvocation {
  argv: string[]
  env: NodeJS.ProcessEnv
  policyPath: string
}

export interface LandstripWrapState {
  generation: number
  config: SandboxRuntimeConfig
}

let sandboxGeneration = 0
let landstripSessionActive = false
let landstripExecutable: string | undefined
let policyDirectory: string | undefined
let policySequence = 0

let exitHookRegistered = false

function policyDirectoryPath(): string {
  if (!exitHookRegistered) {
    exitHookRegistered = true
    process.once('exit', cleanupLandstripPolicies)
  }
  policyDirectory ??= mkdtempSync(join(tmpdir(), 'sandbox-runtime-landstrip-'))
  return policyDirectory
}

export function activateLandstripSession(): void {
  landstripSessionActive = true
}

export function beginLandstripReset(): void {
  landstripSessionActive = false
  sandboxGeneration += 1
  cleanupLandstripPolicies()
}

export function landstripUnavailableReason(): string | undefined {
  let executable: string
  try {
    executable = binaryPath()
  } catch (error) {
    return (error as Error).message
  }

  if (!existsSync(executable)) {
    return `Landstrip binary not found: ${executable}`
  }
  if (landstripExecutable === executable) {
    return undefined
  }

  const doctor = spawnSync(executable, ['doctor'], {
    encoding: 'utf8',
    timeout: 5_000,
    windowsHide: true,
  })
  if (doctor.error) {
    return `Landstrip doctor failed: ${doctor.error.message}`
  }
  if (doctor.status !== 0) {
    const detail = (doctor.stderr || doctor.stdout).trim()
    return `Landstrip doctor reported an unhealthy sandbox${detail ? `: ${detail}` : ''}`
  }

  landstripExecutable = executable
  return undefined
}

/** Use the provisioned native firewall range, never the legacy srt-win range. */
export function landstripProxyPortRange():
  | readonly [number, number]
  | undefined {
  if (getPlatform() !== 'windows' || process.platform !== 'win32')
    return undefined
  const result = spawnSync(binaryPath(), ['windows', 'status'], {
    encoding: 'utf8',
    timeout: 5_000,
    windowsHide: true,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || 'Landstrip Windows status failed')
  }
  const status: unknown = JSON.parse(result.stdout)
  if (
    typeof status !== 'object' ||
    status === null ||
    !('active' in status) ||
    status.active !== 'restrictedUser' ||
    !('installed' in status) ||
    status.installed !== true ||
    !('healthy' in status) ||
    status.healthy !== true ||
    !('proxyPortLow' in status) ||
    typeof status.proxyPortLow !== 'number' ||
    !('proxyPortHigh' in status) ||
    typeof status.proxyPortHigh !== 'number' ||
    !Number.isInteger(status.proxyPortLow) ||
    !Number.isInteger(status.proxyPortHigh) ||
    status.proxyPortLow < 1 ||
    status.proxyPortHigh > 65535 ||
    status.proxyPortLow >= status.proxyPortHigh
  ) {
    throw new Error(
      'Windows sandboxing requires a healthy restricted-user installation. Run "landstrip windows install", then "landstrip windows status".',
    )
  }
  return [status.proxyPortLow, status.proxyPortHigh]
}

export function landstripUnsupportedReason(
  runtimeConfig: SandboxRuntimeConfig,
  enableLogMonitor: boolean,
): string | undefined {
  const platform = getPlatform()
  if (enableLogMonitor && platform !== 'macos') {
    return 'sandbox violation monitoring is not supported by the Landstrip wrapper API'
  }

  if (platform === 'linux') {
    if (runtimeConfig.seccomp !== undefined) {
      return 'custom seccomp configuration is not supported by Landstrip'
    }
    if (
      runtimeConfig.bwrapPath !== undefined ||
      runtimeConfig.socatPath !== undefined
    ) {
      return 'bwrapPath and socatPath are not supported by Landstrip'
    }
    if (runtimeConfig.enableWeakerNestedSandbox) {
      return 'enableWeakerNestedSandbox is not supported by Landstrip'
    }
    if (runtimeConfig.allowNestedUserNamespaces !== undefined) {
      return 'allowNestedUserNamespaces is not supported by Landstrip'
    }
  }

  if (platform === 'windows') {
    if (
      runtimeConfig.windows &&
      Object.keys(runtimeConfig.windows).length > 0
    ) {
      return 'legacy windows settings are not supported by Landstrip'
    }
    if (
      runtimeConfig.network.allowLocalBinding ||
      runtimeConfig.network.allowAllUnixSockets ||
      runtimeConfig.network.allowUnixSockets?.length
    ) {
      return 'local binding and Unix socket policies are not supported by Landstrip on Windows'
    }
  }

  return undefined
}

export function assertLandstripConfig(
  runtimeConfig: SandboxRuntimeConfig,
  enableLogMonitor = false,
): void {
  const reason = landstripUnsupportedReason(runtimeConfig, enableLogMonitor)
  if (reason !== undefined) {
    throw new Error(`Unsupported Landstrip configuration: ${reason}`)
  }
}

function defined<T extends object>(value?: Partial<T>): Partial<T> {
  return Object.fromEntries(
    Object.entries(value ?? {}).filter(([, entry]) => entry !== undefined),
  ) as Partial<T>
}

export function mergeLandstripRuntimeConfig(
  base: SandboxRuntimeConfig,
  override?: Partial<SandboxRuntimeConfig>,
): SandboxRuntimeConfig {
  return {
    ...base,
    ...defined(override),
    network: { ...base.network, ...defined(override?.network) },
    filesystem: {
      ...base.filesystem,
      ...defined(override?.filesystem),
      disabled:
        override?.filesystem !== undefined
          ? (override.filesystem.disabled ?? false)
          : base.filesystem.disabled,
    },
  }
}

const defaultBaseConfig: SandboxRuntimeConfig = {
  network: {
    allowedDomains: undefined as unknown as string[],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: [],
    allowWrite: [],
    denyWrite: [],
  },
}

export function beginLandstripWrap(
  baseConfig: SandboxRuntimeConfig | undefined,
  customConfig: Partial<SandboxRuntimeConfig> | undefined,
): LandstripWrapState {
  if (
    (baseConfig === undefined || !landstripSessionActive) &&
    customConfig === undefined
  ) {
    throw new Error(
      'SandboxManager.initialize() must be called before wrapping',
    )
  }
  const config = mergeLandstripRuntimeConfig(
    baseConfig ?? defaultBaseConfig,
    customConfig,
  )
  assertLandstripConfig(config)
  return { generation: sandboxGeneration, config }
}

export function writeLandstripPolicy(policy: LandstripPolicy): string {
  const policyPath = join(
    policyDirectoryPath(),
    `policy-${process.pid}-${policySequence++}.json`,
  )
  writeFileSync(policyPath, serializeLandstripPolicy(policy), {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  })
  return policyPath
}

export function cleanupLandstripPolicies(): void {
  if (policyDirectory !== undefined) {
    rmSync(policyDirectory, { recursive: true, force: true })
    policyDirectory = undefined
  }
  policySequence = 0
}

function canonicalizeSafePath(
  targetPath: string,
  baseDirectory = process.cwd(),
): string {
  if (getPlatform() === 'windows') {
    targetPath = stripExtendedPathPrefix(expandWindowsEnvRefs(targetPath))
    if (/^[a-z]:/.test(targetPath)) {
      targetPath = targetPath[0]!.toUpperCase() + targetPath.slice(1)
    }
    if (isUncPath(targetPath)) return win32.normalize(targetPath)
    if (process.platform !== 'win32' && /^[A-Z]:/.test(targetPath))
      return win32.normalize(targetPath)
  }
  const expanded = expandTilde(targetPath)
  const absolute = isAbsolute(expanded)
    ? resolve(expanded)
    : resolve(baseDirectory, expanded)
  if (getPlatform() !== 'windows' && absolute.includes('\\')) {
    const { real, rest } = wayTo(absolute)
    return [real || '/', ...rest].join('/').replace(/^\/+/, '/')
  }
  const pending: string[] = []
  let current = absolute
  for (;;) {
    if (current === '/home' && pending.length > 0) return absolute
    try {
      const resolved = realPathOf(current)
      return pending.length === 0
        ? resolved
        : join(resolved, ...pending.reverse())
    } catch {
      const parent = dirname(current)
      if (parent === current) return absolute
      pending.push(basename(current))
      current = parent
    }
  }
}

function toLiteralSelector(literalPath: string): LandstripPathSelector {
  return /[*?[\]]/.test(literalPath) ? { literal: literalPath } : literalPath
}

function isLiteralSelector(selector: LandstripPathSelector): boolean {
  return typeof selector !== 'string'
    ? 'literal' in selector
    : !/[*?[\]]/.test(selector)
}

function escapeGlobAnchor(dir: string): string {
  return dir.replace(/[*?[]/g, '[$&]')
}

function isGlobToken(token: GlobToken): boolean {
  return (
    token.kind !== GlobTokenKind.Text && token.kind !== GlobTokenKind.Separator
  )
}

function renderGlobTokens(tokens: readonly GlobToken[]): string {
  return tokens
    .map(token => {
      switch (token.kind) {
        case GlobTokenKind.Separator:
          return '/'
        case GlobTokenKind.GlobstarSlash:
          return '**/'
        case GlobTokenKind.Globstar:
          return '**'
        case GlobTokenKind.Star:
          return '*'
        case GlobTokenKind.AnyChar:
          return '?'
        case GlobTokenKind.Text:
          return token.text.replace(/\[/g, '[[]')
        case GlobTokenKind.Set:
          return `[${token.members}]`
      }
    })
    .join('')
}

function resolveAgainstCwd(pathPattern: string, cwd: string): string {
  const pre =
    getPlatform() === 'windows'
      ? stripExtendedPathPrefix(expandWindowsEnvRefs(pathPattern))
      : pathPattern
  const expanded = expandTilde(pre)
  return expanded === pre && !isAbsolute(pre) ? resolve(cwd, pre) : pathPattern
}

function resolvesToRootOrDevice(
  targetPath: string,
  baseDirectory: string,
): boolean {
  if (getPlatform() === 'windows') return false
  const expanded = expandTilde(targetPath)
  const absolute = isAbsolute(expanded)
    ? resolve(expanded)
    : resolve(baseDirectory, expanded)
  if (absolute === '/' || isAtOrUnder(absolute, '/dev')) return false
  try {
    const resolved = realPathOf(absolute)
    return resolved === '/' || isAtOrUnder(resolved, '/dev')
  } catch {
    return false
  }
}

function isUnfollowedAllowSymlink(
  targetPath: string,
  baseDirectory: string,
): boolean {
  if (getPlatform() === 'windows') return false
  const expanded = expandTilde(targetPath)
  const absolute = isAbsolute(expanded)
    ? resolve(expanded)
    : resolve(baseDirectory, expanded)
  if (absolute === '/') return false
  const located = nameLocation(absolute, dir =>
    canonicalizeSafePath(dir, baseDirectory),
  )
  try {
    if (!lstatSync(located).isSymbolicLink()) return false
    const resolved = realPathOf(located)
    if (
      (located === '/tmp' || located === '/var' || located === '/etc') &&
      resolved === `/private${located}`
    ) {
      return false
    }
    return true
  } catch {
    return false
  }
}

function resolvePatternSelector(
  raw: string,
  resolvedCwd: string,
  kind: PathListKind = 'deny',
): LandstripPathSelector | undefined {
  if (!containsGlobCharsForPlatform(raw)) {
    if (resolvesToRootOrDevice(raw, resolvedCwd)) return undefined
    if (kind === 'allow' && isUnfollowedAllowSymlink(raw, resolvedCwd)) {
      return undefined
    }
    return toLiteralSelector(canonicalizeSafePath(raw, resolvedCwd))
  }
  const stripped =
    getPlatform() === 'windows'
      ? raw.replace(/[/\\]\*\*$/, '') || '.'
      : removeTrailingGlobSuffix(raw)
  if (!containsGlobCharsForPlatform(stripped)) {
    if (resolvesToRootOrDevice(stripped, resolvedCwd)) return undefined
    if (kind === 'allow' && isUnfollowedAllowSymlink(stripped, resolvedCwd)) {
      return undefined
    }
    return toLiteralSelector(canonicalizeSafePath(stripped, resolvedCwd))
  }
  const pre =
    getPlatform() === 'windows'
      ? stripExtendedPathPrefix(expandWindowsEnvRefs(raw))
      : raw
  const expanded = expandTilde(pre)
  const absolute = isAbsolute(expanded)
    ? expanded
    : resolve(resolvedCwd, expanded)
  const posixAbsolute =
    getPlatform() === 'windows'
      ? toForwardSlashes(absolute)
      : collapseInteriorSpellings(absolute)
  const tokens = parseGlob(posixAbsolute)
  const firstGlobIdx = tokens.findIndex(isGlobToken)
  if (firstGlobIdx === -1) {
    if (resolvesToRootOrDevice(absolute, resolvedCwd)) return undefined
    if (kind === 'allow' && isUnfollowedAllowSymlink(absolute, resolvedCwd)) {
      return undefined
    }
    return toLiteralSelector(canonicalizeSafePath(absolute, resolvedCwd))
  }
  let lastSepIdx = -1
  for (let i = firstGlobIdx - 1; i >= 0; i--) {
    if (tokens[i]!.kind === GlobTokenKind.Separator) {
      lastSepIdx = i
      break
    }
  }
  if (lastSepIdx <= 0) {
    return renderGlobTokens(tokens)
  }
  const baseDir = tokens
    .slice(0, lastSepIdx)
    .map(token =>
      token.kind === GlobTokenKind.Separator
        ? '/'
        : (token as Extract<GlobToken, { kind: GlobTokenKind.Text }>).text,
    )
    .join('')
  if (resolvesToRootOrDevice(baseDir, resolvedCwd)) return undefined
  const canonicalBase = toForwardSlashes(
    canonicalizeSafePath(baseDir, resolvedCwd),
  )
  return `${escapeGlobAnchor(canonicalBase)}${renderGlobTokens(tokens.slice(lastSepIdx))}`
}

function resolveReadingSelector(
  reading: PathReading,
  resolvedCwd: string,
  kind: PathListKind,
): LandstripPathSelector | undefined {
  if (!reading.glob) {
    if (resolvesToRootOrDevice(reading.path, resolvedCwd)) return undefined
    if (
      kind === 'allow' &&
      isUnfollowedAllowSymlink(reading.path, resolvedCwd)
    ) {
      return undefined
    }
    return toLiteralSelector(canonicalizeSafePath(reading.path, resolvedCwd))
  }
  if (resolvesToRootOrDevice(reading.anchor, resolvedCwd)) return undefined
  const canonicalAnchor = toForwardSlashes(
    canonicalizeSafePath(reading.anchor, resolvedCwd),
  )
  const tail = toForwardSlashes(reading.path).slice(
    toForwardSlashes(reading.anchor).length,
  )
  const tailTokens = parseGlob(tail)
  if (!tailTokens.some(isGlobToken)) {
    if (resolvesToRootOrDevice(reading.path, resolvedCwd)) return undefined
    return toLiteralSelector(canonicalizeSafePath(reading.path, resolvedCwd))
  }
  return `${escapeGlobAnchor(canonicalAnchor)}${renderGlobTokens(tailTokens)}`
}

function resolveLiteralSelectors(
  paths: readonly string[] | undefined,
  resolvedCwd: string,
  kind: PathListKind = 'deny',
): LandstripPathSelector[] {
  return (paths ?? []).flatMap(literal => {
    if (resolvesToRootOrDevice(literal, resolvedCwd)) return []
    if (kind === 'allow' && isUnfollowedAllowSymlink(literal, resolvedCwd)) {
      return []
    }
    return [toLiteralSelector(canonicalizeSafePath(literal, resolvedCwd))]
  })
}

function resolveCallerSelectors(
  kind: PathListKind,
  spellings: readonly string[] | undefined,
  literalPaths: readonly string[] | undefined,
  resolvedCwd: string,
): LandstripPathSelector[] {
  return [
    ...(spellings ?? []).flatMap(raw => {
      const resolved = resolvePatternSelector(raw, resolvedCwd, kind)
      return resolved === undefined ? [] : [resolved]
    }),
    ...(spellings ?? []).flatMap(raw =>
      literalReadings(resolveAgainstCwd(raw, resolvedCwd), kind).flatMap(
        reading => {
          const resolved = resolveReadingSelector(reading, resolvedCwd, kind)
          return resolved === undefined ? [] : [resolved]
        },
      ),
    ),
    ...resolveLiteralSelectors(literalPaths, resolvedCwd, kind),
  ]
}

function writableRootsUnderCwd(
  cwd: string,
  allowWrite?: readonly string[],
): string[] {
  const resolvedCwd = canonicalizeSafePath(cwd, cwd)
  if (allowWrite === undefined) return [resolvedCwd]
  const roots: string[] = []
  for (const raw of allowWrite) {
    const trimmed = raw.replace(/[/\\]\*\*$/, '') || '.'
    const base = canonicalizeSafePath(trimmed, resolvedCwd)
    if (pathUnderDirectory(resolvedCwd, base)) {
      return [resolvedCwd]
    }
    if (pathUnderDirectory(base, resolvedCwd)) {
      roots.push(base)
    }
  }
  return mergeArray([], roots)
}

/** Write denials applied whenever filesystem restrictions are enabled. */
export function getLandstripMandatoryDenyWrite(
  cwd: string,
  allowGitConfig = false,
  allowWrite?: readonly string[],
): LandstripPathSelector[] {
  const resolvedCwd = canonicalizeSafePath(cwd, cwd)
  const deny: LandstripPathSelector[] = []
  const recursiveRoots = writableRootsUnderCwd(resolvedCwd, allowWrite).map(
    escapeGlobAnchor,
  )
  for (const fileName of DANGEROUS_FILES) {
    deny.push(toLiteralSelector(resolve(resolvedCwd, fileName)))
    for (const root of recursiveRoots) {
      deny.push(resolve(root, '**', fileName))
    }
  }
  for (const directoryName of getDangerousDirectories()) {
    deny.push(toLiteralSelector(resolve(resolvedCwd, directoryName)))
    for (const root of recursiveRoots) {
      deny.push(
        resolve(root, '**', directoryName),
        resolve(root, '**', directoryName, '**'),
      )
    }
  }
  deny.push(toLiteralSelector(resolve(resolvedCwd, '.git', 'hooks')))
  for (const root of recursiveRoots) {
    deny.push(
      resolve(root, '**', '.git', 'hooks'),
      resolve(root, '**', '.git', 'hooks', '**'),
    )
  }
  if (!allowGitConfig) {
    deny.push(toLiteralSelector(resolve(resolvedCwd, '.git', 'config')))
    for (const root of recursiveRoots) {
      deny.push(resolve(root, '**', '.git', 'config'))
    }
  }
  return mergeArray([], deny)
}

export function buildLandstripPolicy(
  options: BuildLandstripPolicyOptions,
): LandstripPolicy {
  const { cwd, needsNetworkRestriction, readConfig, writeConfig } = options
  const platform = options.platform ?? (getPlatform() as LandstripPlatform)
  const resolvedCwd = canonicalizeSafePath(cwd, cwd)
  const ownAllowRead = readConfig?.ownAllowWithinDeny ?? []
  const credentialDenyAlways = (readConfig?.credentialDenyOnly ?? []).filter(
    deny =>
      !ownAllowRead.some(
        allow =>
          pathUnderDirectory(allow, deny) ||
          matchesPathPattern(allow, [deny], resolvedCwd),
      ),
  )
  const maskedPaths = [
    ...(options.maskedFileBinds ?? []).map(binding => binding.realPath),
    ...(options.degradeToDenyPaths ?? []),
  ]
  const unlistableDenyDirs = readConfig?.unlistableDenyDirs ?? []
  const mandatoryDenyWrite = writeConfig
    ? (options.mandatoryDenyWrite ?? []).flatMap(entry => {
        if (typeof entry !== 'string') return [entry]
        const resolved = resolvePatternSelector(entry, resolvedCwd, 'deny')
        return resolved === undefined ? [] : [resolved]
      })
    : []

  const denyReadEntries = mergeArray(
    [],
    readConfig
      ? [
          ...resolveCallerSelectors(
            'deny',
            readConfig.denyOnly,
            readConfig.literalDenyOnly,
            resolvedCwd,
          ),
          ...resolveLiteralSelectors(maskedPaths, resolvedCwd, 'deny'),
        ]
      : resolveLiteralSelectors(maskedPaths, resolvedCwd, 'deny'),
  )
  const deniesFilesystemRoot =
    readConfig !== undefined &&
    [...readConfig.denyOnly, ...(readConfig.literalDenyOnly ?? [])].some(
      entry =>
        !resolvesToRootOrDevice(entry, resolvedCwd) &&
        canonicalizeSafePath(entry, resolvedCwd) === '/',
    )

  return buildSharedLandstripPolicy({
    filesystem: {
      denyRead: denyReadEntries,
      denyReadAlways: mergeArray(
        [],
        [
          ...resolveCallerSelectors(
            'deny',
            credentialDenyAlways,
            undefined,
            resolvedCwd,
          ),
          ...resolveLiteralSelectors(
            [...unlistableDenyDirs, ...maskedPaths],
            resolvedCwd,
            'deny',
          ),
        ],
      ),
      allowRead: readConfig
        ? mergeArray(
            [],
            [
              ...(platform !== 'windows' &&
              denyReadEntries.length > 0 &&
              !deniesFilesystemRoot
                ? ['/']
                : []),
              ...resolveCallerSelectors(
                'allow',
                readConfig.allowWithinDeny,
                readConfig.literalAllowWithinDeny,
                resolvedCwd,
              ),
              ...resolveLiteralSelectors(ownAllowRead, resolvedCwd, 'allow'),
            ],
          )
        : [],
      allowWrite: writeConfig
        ? mergeArray(
            [],
            resolveCallerSelectors(
              'allow',
              writeConfig.allowOnly,
              writeConfig.literalAllowOnly,
              resolvedCwd,
            ),
          )
        : [parse(resolvedCwd).root],
      denyWrite: writeConfig
        ? mergeArray(
            [],
            [
              ...resolveCallerSelectors(
                'deny',
                writeConfig.denyWithinAllow,
                writeConfig.literalDenyWithinAllow,
                resolvedCwd,
              ),
              ...mandatoryDenyWrite,
            ],
          )
        : [],
      denyWriteAlways: writeConfig
        ? mergeArray(
            [],
            [
              ...mandatoryDenyWrite.filter(isLiteralSelector),
              ...resolveLiteralSelectors(unlistableDenyDirs, resolvedCwd),
            ],
          )
        : [],
    },
    network: {
      allowNetwork: !needsNetworkRestriction,
      allowLocalBinding: options.allowLocalBinding ?? false,
      allowAllUnixSockets: options.allowAllUnixSockets ?? false,
      allowUnixSockets: [...(options.allowUnixSockets ?? [])],
    },
    httpProxyPort: needsNetworkRestriction ? options.httpProxyPort : null,
    socksProxyPort: needsNetworkRestriction ? options.socksProxyPort : null,
    macos: {
      allowTrustd: options.enableWeakerNetworkIsolation ?? false,
      allowMachLookup: [...(options.allowMachLookup ?? [])],
      allowAppleEvents: options.allowAppleEvents ?? false,
      allowPty: options.allowPty ?? false,
      ...(options.logTag !== undefined ? { logTag: options.logTag } : {}),
    },
    windows: {
      appContainerMode: 'lpac',
      allowLoopback:
        needsNetworkRestriction || Boolean(options.allowLocalBinding),
    },
  })
}

function environmentAssignments(
  options: WrapCommandWithLandstripOptions,
): string[] {
  const assignments = generateProxyEnvVars(
    options.httpProxyPort,
    options.socksProxyPort,
    options.caCertPath,
    options.proxyAuthToken,
    options.writeConfig === undefined,
    encodeSandboxedCommand(options.commandId ?? options.command),
  )

  const javaToolOptions = buildJavaToolOptions({
    agentJarPath: options.javaAgentJarPath,
    flags:
      options.platform === 'macos' &&
      options.needsNetworkRestriction &&
      (options.allowLocalBinding ||
        options.httpProxyPort !== undefined ||
        options.socksProxyPort !== undefined)
        ? ['-Djava.net.preferIPv4Stack=true']
        : [],
    unsetEnvVars: [...(options.unsetEnvVars ?? [])],
    inherited: process.env.JAVA_TOOL_OPTIONS,
  })
  if (javaToolOptions !== undefined) {
    assignments.push(`JAVA_TOOL_OPTIONS=${javaToolOptions}`)
  }

  if (options.gitSafeDirectories?.length) {
    const safeDirs =
      options.platform === 'windows'
        ? options.gitSafeDirectories.map(dir =>
            toForwardSlashes(
              stripExtendedPathPrefix(expandWindowsEnvRefs(dir)),
            ),
          )
        : options.gitSafeDirectories
    const git = buildPosixGitSafeDirEnv({
      safeDirs,
      unsetEnvVars: options.unsetEnvVars,
      setEnvVars: options.setEnvVars,
    })
    assignments.push(
      ...Object.entries(git).map(([name, value]) => `${name}=${value}`),
    )
  }
  return assignments
}

export function wrapCommandWithLandstrip(
  options: WrapCommandWithLandstripOptions,
): LandstripInvocation {
  const landstripPath =
    options.landstripPath ?? (landstripExecutable ??= binaryPath())
  const policyPath = writeLandstripPolicy(buildLandstripPolicy(options))
  try {
    const landstripArgs = [
      landstripPath,
      'run',
      '-p',
      policyPath,
      '--',
      options.shell.exe,
      ...options.shell.args,
      options.command,
    ]
    const assignments = environmentAssignments(options)
    const set = Object.entries(options.setEnvVars ?? {}).map(
      ([name, value]) => `${name}=${value}`,
    )
    if (options.platform === 'windows') {
      const env = { ...process.env }
      for (const name of [
        ...(options.unsetEnvVars ?? []),
        ...Object.keys(options.setEnvVars ?? {}),
      ]) {
        for (const key of Object.keys(env)) {
          if (key.toLowerCase() === name.toLowerCase()) delete env[key]
        }
      }
      for (const entry of [...set, ...assignments]) {
        const equals = entry.indexOf('=')
        env[entry.slice(0, equals)] = entry.slice(equals + 1)
      }
      return { argv: landstripArgs, env, policyPath }
    }
    const unset = (options.unsetEnvVars ?? []).flatMap(name => ['-u', name])
    return {
      argv: ['env', ...unset, ...set, ...assignments, ...landstripArgs],
      env: process.env,
      policyPath,
    }
  } catch (error) {
    rmSync(policyPath, { force: true })
    throw error
  }
}

export function quoteLandstripInvocation(
  invocation: Pick<LandstripInvocation, 'argv'>,
): string {
  return quote(invocation.argv)
}

function resolvePosixShell(
  name: string | WindowsBinShell = 'bash',
): LandstripShell {
  if (typeof name !== 'string') {
    throw new Error('binShell object form is Windows-only')
  }
  const exe = whichSync(name)
  if (exe === null) throw new Error(`Shell '${name}' not found in PATH`)
  return { exe, args: ['-c'] }
}

export function wrapWithLandstrip(
  state: LandstripWrapState,
  options: Omit<
    WrapCommandWithLandstripOptions,
    | 'platform'
    | 'shell'
    | 'landstripPath'
    | 'allowLocalBinding'
    | 'allowUnixSockets'
    | 'allowAllUnixSockets'
    | 'enableWeakerNetworkIsolation'
    | 'allowMachLookup'
    | 'allowAppleEvents'
    | 'allowPty'
    | 'mandatoryDenyWrite'
  > & {
    platform: Platform
    binShell?: string | WindowsBinShell
  },
): LandstripInvocation {
  if (state.generation !== sandboxGeneration) {
    throw new Error('Sandbox was reset while wrapping the command')
  }
  if (options.platform === 'unknown') {
    throw new Error('Unsupported platform')
  }
  const shell =
    options.platform === 'windows'
      ? parseWindowsBinShell(options.binShell)
      : resolvePosixShell(options.binShell)
  const { config } = state
  return wrapCommandWithLandstrip({
    ...options,
    platform: options.platform,
    shell,
    allowLocalBinding: config.network.allowLocalBinding,
    allowUnixSockets: config.network.allowUnixSockets,
    allowAllUnixSockets: config.network.allowAllUnixSockets,
    enableWeakerNetworkIsolation: config.enableWeakerNetworkIsolation,
    allowMachLookup: config.network.allowMachLookup,
    allowAppleEvents: config.allowAppleEvents,
    allowPty: config.allowPty,
    writeConfig: options.writeConfig,
    mandatoryDenyWrite:
      options.writeConfig === undefined
        ? []
        : getLandstripMandatoryDenyWrite(
            options.cwd,
            config.filesystem.allowGitConfig ?? false,
            [
              ...options.writeConfig.allowOnly,
              ...(options.writeConfig.literalAllowOnly ?? []),
            ],
          ),
  })
}
