import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, readFileSync, readdirSync, utimesSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * @typedef {{ path: string, contains: string, contentTypes: string[] }} Probe
 * @typedef {{ appId: string, region: string, branch: string, domain: string, role: string, requiredHeaders: Record<string, string>, probes: Probe[] }} SiteConfig
 * @typedef {{ cwd?: string, input?: string, env?: Record<string, string> }} RunOptions
 * @typedef {(command: string, args: string[], options?: RunOptions) => string} Runner
 * @typedef {{ run: Runner, fetch: typeof fetch, sleep: (seconds: number) => Promise<void>, log: (line: string) => void }} Tools
 * @typedef {{ jobId: string, zipUploadUrl: string }} Deployment
 * @typedef {{ repository: string, commit: string, version: string, sha256: string, token: string }} StagingGate
 * @typedef {{ context: string, state: string, description: string }} CommitStatus
 */
export class SiteDeploy {
  static VERSION_FILE = 'site-version.json';
  static FIXED_TIME = new Date('1980-01-01T00:00:00Z');
  static FILE_MODE = 0o644;
  static DIRECTORY_MODE = 0o755;
  static SUCCEEDED = 'SUCCEED';
  static FAILED_STATES = ['FAILED', 'CANCELLED'];
  static JOB_ATTEMPTS = 80;
  static JOB_WAIT_SECONDS = 15;
  static VERSION_ATTEMPTS = 12;
  static VERSION_WAIT_SECONDS = 15;
  static STAGING_CONTEXT = 'site-staging/floci';
  static STAGING_PASSED = 'success';
  static STAGING_FAILED = ['failure', 'error'];
  static STAGING_MISSING = { context: 'site-staging/floci', state: 'missing', description: '' };
  static STAGING_ATTEMPTS = 40;
  static STAGING_WAIT_SECONDS = 30;
  static SHA256_PREFIX_LENGTH = 12;
  static GITHUB_API = 'https://api.github.com';

  /** @param {Tools} tools */
  constructor(tools) {
    this.tools = tools;
  }

  /**
   * @param {string} directory
   * @param {string} version
   * @param {string} commit
   * @param {string} output
   * @returns {string}
   */
  package(directory, version, commit, output) {
    writeFileSync(join(directory, SiteDeploy.VERSION_FILE), `${JSON.stringify({ version, commit })}\n`);
    const files = this.#normalizeTree(directory);
    this.tools.run('zip', ['-X', '-D', '-q', output, '-@'], { cwd: directory, input: `${files.join('\n')}\n`, env: { TZ: 'UTC' } });
    return this.checksum(output);
  }

  /**
   * @param {string} file
   * @returns {string}
   */
  checksum(file) {
    return createHash('sha256').update(readFileSync(file)).digest('hex');
  }

  /**
   * @param {string} file
   * @param {string} expected
   */
  verify(file, expected) {
    this.#requireEqual(this.checksum(file), expected.trim(), `SHA-256 of ${file}`);
  }

  /**
   * @param {string} version
   * @param {string} sha256
   * @returns {string}
   */
  stagingDescription(version, sha256) {
    return `${version} ${sha256.slice(0, SiteDeploy.SHA256_PREFIX_LENGTH)}`;
  }

  /** @param {StagingGate} gate */
  async waitForStaging(gate) {
    const expected = this.stagingDescription(gate.version, gate.sha256);
    await this.#pollStaging(gate, expected);
    this.tools.log(`${SiteDeploy.STAGING_CONTEXT} passed on ${gate.commit}: ${expected}`);
  }

  /** @param {SiteConfig} config */
  checkHeaders(config) {
    const policy = this.#headerPolicy(config);
    const missing = this.#missingFromPolicy(policy, config.requiredHeaders);
    this.#requireNothingMissing(missing, 'The Amplify header policy lacks');
  }

  /**
   * @param {SiteConfig} config
   * @param {string} zip
   */
  async deploy(config, zip) {
    const branch = this.#branch(config);
    const deployment = /** @type {Deployment} */ (this.#aws('create-deployment', ['--app-id', config.appId, '--branch-name', branch], config.region));
    await this.#upload(deployment.zipUploadUrl, zip);
    this.#aws('start-deployment', ['--app-id', config.appId, '--branch-name', branch, '--job-id', deployment.jobId], config.region);
    await this.#waitForJob(config, branch, deployment.jobId);
  }

  /**
   * @param {SiteConfig} config
   * @returns {Promise<string>}
   */
  async liveVersion(config) {
    const response = await this.tools.fetch(this.#versionUrl(config), { redirect: 'follow' });
    return this.#versionFrom(response);
  }

  /**
   * @param {SiteConfig} config
   * @param {string} version
   */
  async probe(config, version) {
    await this.#waitForVersion(config, version);
    const failures = await this.#probeFailures(config);
    this.#requireNothingMissing(failures, 'Probes failed');
    this.tools.log(`${this.origin(config)} serves ${version}; ${config.probes.length} probes passed`);
  }

  /**
   * @param {SiteConfig} config
   * @returns {string}
   */
  origin(config) {
    return `https://${config.domain}`;
  }

  /**
   * @param {StagingGate} gate
   * @param {string} expected
   */
  async #pollStaging(gate, expected) {
    for (let attempt = 0; attempt < SiteDeploy.STAGING_ATTEMPTS; attempt += 1) {
      if (this.#stagingPassed(await this.#latestStagingStatus(gate), expected)) return;
      await this.tools.sleep(SiteDeploy.STAGING_WAIT_SECONDS);
    }
    throw new Error(`No ${SiteDeploy.STAGING_CONTEXT} success "${expected}" on ${gate.commit} in time`);
  }

  /**
   * @param {StagingGate} gate
   * @returns {Promise<CommitStatus>}
   */
  async #latestStagingStatus(gate) {
    const response = await this.tools.fetch(`${SiteDeploy.GITHUB_API}/repos/${gate.repository}/commits/${gate.commit}/statuses?per_page=100`, {
      headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${gate.token}`, 'x-github-api-version': '2022-11-28' },
    });
    this.#requireOk(response, 'Reading the commit statuses');
    return this.#newestStagingStatus(await response.json());
  }

  /**
   * @param {CommitStatus[]} statuses
   * @returns {CommitStatus}
   */
  #newestStagingStatus(statuses) {
    return statuses.find((status) => status.context === SiteDeploy.STAGING_CONTEXT) ?? SiteDeploy.STAGING_MISSING;
  }

  /**
   * @param {CommitStatus} status
   * @param {string} expected
   * @returns {boolean}
   */
  #stagingPassed(status, expected) {
    this.tools.log(`${SiteDeploy.STAGING_CONTEXT}: ${status.state} ${status.description}`);
    this.#requireStagingNotFailed(status);
    return this.#isExpectedSuccess(status, expected);
  }

  /** @param {CommitStatus} status */
  #requireStagingNotFailed(status) {
    if (SiteDeploy.STAGING_FAILED.includes(status.state)) throw new Error(`Staging on Floci reported ${status.state}: ${status.description}`);
  }

  /**
   * @param {CommitStatus} status
   * @param {string} expected
   * @returns {boolean}
   */
  #isExpectedSuccess(status, expected) {
    return status.state === SiteDeploy.STAGING_PASSED && status.description === expected;
  }

  /**
   * @param {SiteConfig} config
   * @returns {string}
   */
  #headerPolicy(config) {
    return this.#aws('get-app', ['--app-id', config.appId], config.region).app.customHeaders ?? '';
  }

  /**
   * @param {string} directory
   * @returns {string[]}
   */
  #normalizeTree(directory) {
    const files = [];
    for (const entry of readdirSync(directory, { recursive: true, withFileTypes: true })) {
      files.push(...this.#normalizeEntry(directory, join(entry.parentPath, entry.name), entry.isDirectory()));
    }
    utimesSync(directory, SiteDeploy.FIXED_TIME, SiteDeploy.FIXED_TIME);
    return files.sort();
  }

  /**
   * @param {string} directory
   * @param {string} path
   * @param {boolean} isDirectory
   * @returns {string[]}
   */
  #normalizeEntry(directory, path, isDirectory) {
    chmodSync(path, this.#mode(isDirectory));
    utimesSync(path, SiteDeploy.FIXED_TIME, SiteDeploy.FIXED_TIME);
    return this.#zipEntries(directory, path, isDirectory);
  }

  /**
   * @param {boolean} isDirectory
   * @returns {number}
   */
  #mode(isDirectory) {
    return isDirectory ? SiteDeploy.DIRECTORY_MODE : SiteDeploy.FILE_MODE;
  }

  /**
   * @param {string} directory
   * @param {string} path
   * @param {boolean} isDirectory
   * @returns {string[]}
   */
  #zipEntries(directory, path, isDirectory) {
    return isDirectory ? [] : [relative(directory, path)];
  }

  /**
   * @param {string} operation
   * @param {string[]} args
   * @param {string} region
   * @returns {any}
   */
  #aws(operation, args, region) {
    return JSON.parse(this.tools.run('aws', ['amplify', operation, ...args, '--region', region, '--output', 'json']) || '{}');
  }

  /**
   * @param {string} url
   * @param {string} zip
   */
  async #upload(url, zip) {
    const response = await this.tools.fetch(url, { method: 'PUT', body: readFileSync(zip) });
    this.#requireOk(response, 'Upload of the site zip');
  }

  /**
   * @param {SiteConfig} config
   * @returns {string}
   */
  #branch(config) {
    if (!config.branch) throw new Error('The site config names no Amplify branch');
    return config.branch;
  }

  /**
   * @param {SiteConfig} config
   * @param {string} branch
   * @param {string} jobId
   */
  async #waitForJob(config, branch, jobId) {
    for (let attempt = 0; attempt < SiteDeploy.JOB_ATTEMPTS; attempt += 1) {
      const status = this.#aws('get-job', ['--app-id', config.appId, '--branch-name', branch, '--job-id', jobId], config.region).job.summary.status;
      this.tools.log(`Amplify ${branch} job ${jobId}: ${status}`);
      if (this.#jobFinished(status)) return;
      await this.tools.sleep(SiteDeploy.JOB_WAIT_SECONDS);
    }
    throw new Error(`Amplify ${branch} job ${jobId} did not finish in time`);
  }

  /**
   * @param {string} status
   * @returns {boolean}
   */
  #jobFinished(status) {
    if (SiteDeploy.FAILED_STATES.includes(status)) throw new Error(`Amplify job ended ${status}`);
    return status === SiteDeploy.SUCCEEDED;
  }

  /**
   * @param {SiteConfig} config
   * @param {string} version
   */
  async #waitForVersion(config, version) {
    for (let attempt = 0; attempt < SiteDeploy.VERSION_ATTEMPTS; attempt += 1) {
      if ((await this.liveVersion(config)) === version) return;
      await this.tools.sleep(SiteDeploy.VERSION_WAIT_SECONDS);
    }
    throw new Error(`${this.origin(config)} does not serve ${version}`);
  }

  /**
   * @param {SiteConfig} config
   * @returns {string}
   */
  #versionUrl(config) {
    return `${this.origin(config)}/${SiteDeploy.VERSION_FILE}?check=${Date.now()}`;
  }

  /**
   * @param {Response} response
   * @returns {Promise<string>}
   */
  async #versionFrom(response) {
    return response.ok ? this.#versionField(await response.json()) : '';
  }

  /**
   * @param {{ version?: string }} record
   * @returns {string}
   */
  #versionField(record) {
    return record.version ?? '';
  }

  /**
   * @param {SiteConfig} config
   * @returns {Promise<string[]>}
   */
  async #probeFailures(config) {
    const failures = [];
    for (const probe of config.probes) {
      failures.push(...(await this.#checkProbe(this.origin(config), probe, config.requiredHeaders)));
    }
    return failures;
  }

  /**
   * @param {string} origin
   * @param {Probe} probe
   * @param {Record<string, string>} requiredHeaders
   * @returns {Promise<string[]>}
   */
  async #checkProbe(origin, probe, requiredHeaders) {
    const response = await this.tools.fetch(`${origin}${probe.path}`, { redirect: 'follow' });
    const body = await response.text();
    return [
      ...this.#statusFailure(probe, response),
      ...this.#contentFailure(probe, body),
      ...this.#typeFailure(probe, this.#contentType(response)),
      ...this.#missingFromResponse(probe, response.headers, requiredHeaders),
    ];
  }

  /**
   * @param {Probe} probe
   * @param {Response} response
   * @returns {string[]}
   */
  #statusFailure(probe, response) {
    return response.ok ? [] : [`${probe.path} returned ${response.status}`];
  }

  /**
   * @param {Probe} probe
   * @param {string} body
   * @returns {string[]}
   */
  #contentFailure(probe, body) {
    return body.includes(probe.contains) ? [] : [`${probe.path} lacks ${JSON.stringify(probe.contains)}`];
  }

  /**
   * @param {Probe} probe
   * @param {string} contentType
   * @returns {string[]}
   */
  #typeFailure(probe, contentType) {
    return this.#typeAllowed(probe.contentTypes, contentType) ? [] : [`${probe.path} has content type ${contentType}`];
  }

  /**
   * @param {string[]} allowed
   * @param {string} contentType
   * @returns {boolean}
   */
  #typeAllowed(allowed, contentType) {
    if (allowed.length === 0) return true;
    return this.#startsWithAny(contentType, allowed);
  }

  /**
   * @param {string} text
   * @param {string[]} prefixes
   * @returns {boolean}
   */
  #startsWithAny(text, prefixes) {
    return prefixes.some((prefix) => text.startsWith(prefix));
  }

  /**
   * @param {Response} response
   * @returns {string}
   */
  #contentType(response) {
    return response.headers.get('content-type') ?? '';
  }

  /**
   * @param {Probe} probe
   * @param {Headers} headers
   * @param {Record<string, string>} requiredHeaders
   * @returns {string[]}
   */
  #missingFromResponse(probe, headers, requiredHeaders) {
    return Object.entries(requiredHeaders)
      .filter(([name, value]) => headers.get(name) !== value)
      .map(([name]) => `${probe.path} lacks header ${name}`);
  }

  /**
   * @param {string} policy
   * @param {Record<string, string>} requiredHeaders
   * @returns {string[]}
   */
  #missingFromPolicy(policy, requiredHeaders) {
    const text = this.#collapseSpaces(policy).toLowerCase();
    return Object.entries(requiredHeaders)
      .filter((header) => !this.#policyHas(text, header))
      .map(([name]) => name);
  }

  /**
   * @param {string} text
   * @param {[string, string]} header
   * @returns {boolean}
   */
  #policyHas(text, [name, value]) {
    return text.includes(name.toLowerCase()) && text.includes(this.#collapseSpaces(value).toLowerCase());
  }

  /**
   * @param {string} text
   * @returns {string}
   */
  #collapseSpaces(text) {
    return text.replace(/\s+/g, ' ');
  }

  /**
   * @param {Response} response
   * @param {string} action
   */
  #requireOk(response, action) {
    if (!response.ok) throw new Error(`${action} failed with HTTP ${response.status}`);
  }

  /**
   * @param {string} actual
   * @param {string} expected
   * @param {string} subject
   */
  #requireEqual(actual, expected, subject) {
    if (actual !== expected) throw new Error(`${subject} is ${actual}, expected ${expected}`);
  }

  /**
   * @param {string[]} missing
   * @param {string} message
   */
  #requireNothingMissing(missing, message) {
    if (missing.length > 0) throw new Error(`${message}: ${missing.join('; ')}`);
  }

  /**
   * @param {string} command
   * @param {string[]} args
   * @param {RunOptions} [options]
   * @returns {string}
   */
  static run(command, args, options = {}) {
    const result = spawnSync(command, args, { cwd: options.cwd, input: options.input, env: { ...process.env, ...options.env }, encoding: 'utf8' });
    SiteDeploy.#requireSuccess(command, result);
    return result.stdout;
  }

  /**
   * @param {string} command
   * @param {import('node:child_process').SpawnSyncReturns<string>} result
   */
  static #requireSuccess(command, result) {
    if (result.status !== 0) throw new Error(`${command} failed (${result.status ?? result.error?.message}): ${result.stderr}`);
  }

  /** @returns {SiteDeploy} */
  static live() {
    return new SiteDeploy({
      run: SiteDeploy.run,
      fetch: globalThis.fetch,
      sleep: (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000)),
      log: (line) => console.log(line),
    });
  }

  /**
   * @param {string} path
   * @returns {SiteConfig}
   */
  static config(path) {
    return JSON.parse(readFileSync(path, 'utf8'));
  }

  /**
   * @param {string[]} argv
   * @param {SiteDeploy} [site]
   * @param {Record<string, string | undefined>} [environment]
   */
  static async main(argv, site = SiteDeploy.live(), environment = process.env) {
    const [command, ...args] = argv;
    const output = await SiteDeploy.#command(site, command, args, environment);
    console.log(output);
  }

  /**
   * @param {SiteDeploy} site
   * @param {string} command
   * @param {string[]} args
   * @param {Record<string, string | undefined>} environment
   * @returns {Promise<string>}
   */
  static async #command(site, command, args, environment) {
    switch (command) {
      case 'package':
        return site.package(args[0], args[1], args[2], args[3]);
      case 'verify':
        site.verify(args[0], args[1]);
        return 'verified';
      case 'wait-staging':
        await site.waitForStaging({ repository: args[0], commit: args[1], version: args[2], sha256: args[3], token: environment.GITHUB_TOKEN ?? '' });
        return 'staging passed';
      case 'check-headers':
        site.checkHeaders(SiteDeploy.config(args[0]));
        return 'header policy covers the required headers';
      case 'deploy':
        await site.deploy(SiteDeploy.config(args[0]), args[1]);
        return 'deployed';
      case 'live-version':
        return site.liveVersion(SiteDeploy.config(args[0]));
      case 'probe':
        await site.probe(SiteDeploy.config(args[0]), args[1]);
        return 'probes passed';
      default:
        throw new Error('Usage: site-deploy.mjs package|verify|wait-staging|check-headers|deploy|live-version|probe ...');
    }
  }
}

if (import.meta.main) await SiteDeploy.main(process.argv.slice(2));
