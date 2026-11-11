import { describe, expect, spyOn, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SiteDeploy } from './site-deploy.mjs';

const CONFIG = {
  appId: 'd000000000000',
  region: 'ca-central-1',
  branch: 'production',
  domain: 'site.example',
  role: 'arn:aws:iam::000000000000:role/site-site-deploy-production',
  requiredHeaders: { 'x-content-type-options': 'nosniff' },
  probes: [{ path: '/', contains: 'Welcome', contentTypes: ['text/html'] }],
};

const SHA256 = '99682b0a0ca3dc5ef7f397d8af10427180f209fb48a9ef4016ce3ed509150fdc';
const STATUSES_URL = 'https://api.github.com/repos/d31ma/SITE/commits/abc123/statuses';
const GATE = { repository: 'd31ma/SITE', commit: 'abc123', version: '26.46.01', sha256: SHA256, token: 'github-token' };

function fakeTools(responses = {}) {
  const calls = [];
  const fetched = [];
  const requestHeaders = [];
  const logs = [];
  const sleeps = [];
  const jobStates = [...(responses.jobStates ?? [])];
  const statusRounds = [...(responses.statusRounds ?? [])];
  const pages = responses.pages ?? {};
  return {
    calls,
    fetched,
    requestHeaders,
    logs,
    sleeps,
    tools: {
      run: (command, args, options) => {
        calls.push([command, ...args]);
        if (command === 'zip') return SiteDeploy.run(command, args, options);
        if (args[1] === 'create-deployment') return JSON.stringify({ jobId: '7', zipUploadUrl: 'https://upload.example/zip' });
        if (args[1] === 'get-job') return JSON.stringify({ job: { summary: { status: jobStates.shift() } } });
        if (args[1] === 'get-app') return JSON.stringify({ app: { customHeaders: responses.policy ?? '' } });
        return '';
      },
      fetch: async (url, options = {}) => {
        fetched.push([url, options.method ?? 'GET']);
        requestHeaders.push(options.headers);
        if (url.split('?')[0] === STATUSES_URL) return Response.json(statusRounds.shift() ?? [], { status: responses.statusCode ?? 200 });
        const page = pages[url.split('?')[0]] ?? { status: 404, body: '' };
        return new Response(page.body, { status: page.status ?? 200, headers: page.headers ?? {} });
      },
      sleep: async (seconds) => {
        sleeps.push(seconds);
      },
      log: (line) => logs.push(line),
    },
  };
}

function status(state, description, context = 'site-staging/floci') {
  return { context, state, description };
}

function siteDirectory() {
  const directory = mkdtempSync(join(tmpdir(), 'site-deploy-'));
  mkdirSync(join(directory, 'docs'));
  writeFileSync(join(directory, 'index.html'), '<h1>Welcome</h1>');
  writeFileSync(join(directory, 'docs', 'index.html'), '<h1>Docs</h1>');
  return directory;
}

function zipFile() {
  const zip = join(mkdtempSync(join(tmpdir(), 'site-up-')), 'site.zip');
  writeFileSync(zip, 'zip');
  return zip;
}

function configFile() {
  const path = join(mkdtempSync(join(tmpdir(), 'site-config-')), 'site-deploy.json');
  writeFileSync(path, JSON.stringify(CONFIG));
  return path;
}

function productionSite() {
  return {
    'https://upload.example/zip': { status: 200, body: '' },
    'https://site.example/site-version.json': { body: '{"version":"26.46.01"}' },
    'https://site.example/': { body: 'Welcome', headers: { 'content-type': 'text/html; charset=utf-8', 'x-content-type-options': 'nosniff' } },
  };
}

async function printed(argv, fake, environment = {}) {
  const log = spyOn(console, 'log').mockImplementation(() => {});
  await SiteDeploy.main(argv, new SiteDeploy(fake.tools), environment);
  const output = log.mock.calls.at(-1)?.[0];
  log.mockRestore();
  return output;
}

describe('SiteDeploy.package', () => {
  test('builds the same zip twice from the same site', () => {
    const output = mkdtempSync(join(tmpdir(), 'site-zip-'));
    const site = new SiteDeploy(fakeTools().tools);
    const first = site.package(siteDirectory(), '26.46.01', 'abc123', join(output, 'first.zip'));
    const second = site.package(siteDirectory(), '26.46.01', 'abc123', join(output, 'second.zip'));
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });

  test('writes site-version.json into the site', () => {
    const directory = siteDirectory();
    new SiteDeploy(fakeTools().tools).package(directory, '26.46.01', 'abc123', join(mkdtempSync(join(tmpdir(), 'site-zip-')), 'site.zip'));
    expect(JSON.parse(readFileSync(join(directory, 'site-version.json'), 'utf8'))).toEqual({ version: '26.46.01', commit: 'abc123' });
  });

  test('stores the files in sorted order with no directory entries', () => {
    const zip = join(mkdtempSync(join(tmpdir(), 'site-zip-')), 'site.zip');
    new SiteDeploy(fakeTools().tools).package(siteDirectory(), '26.46.01', 'abc123', zip);
    expect(SiteDeploy.run('unzip', ['-Z1', zip]).trim().split('\n')).toEqual(['docs/index.html', 'index.html', 'site-version.json']);
  });
});

describe('SiteDeploy.verify', () => {
  test('accepts the matching checksum', () => {
    const file = zipFile();
    const site = new SiteDeploy(fakeTools().tools);
    expect(() => site.verify(file, `${site.checksum(file)}\n`)).not.toThrow();
  });

  test('rejects a different checksum', () => {
    expect(() => new SiteDeploy(fakeTools().tools).verify(zipFile(), '0'.repeat(64))).toThrow('SHA-256');
  });
});

describe('SiteDeploy.waitForStaging', () => {
  test('describes the zip as the version and the first 12 hex of its SHA-256', () => {
    expect(new SiteDeploy(fakeTools().tools).stagingDescription('26.46.01', SHA256)).toBe('26.46.01 99682b0a0ca3');
  });

  test('passes on the newest site-staging/floci success for this zip', async () => {
    const fake = fakeTools({ statusRounds: [[status('success', '26.46.01 99682b0a0ca3'), status('pending', '26.46.01 99682b0a0ca3')]] });
    await new SiteDeploy(fake.tools).waitForStaging(GATE);
    expect(fake.logs.at(-1)).toBe('site-staging/floci passed on abc123: 26.46.01 99682b0a0ca3');
    expect(fake.sleeps).toEqual([]);
  });

  test('reads the statuses with the workflow token', async () => {
    const fake = fakeTools({ statusRounds: [[status('success', '26.46.01 99682b0a0ca3')]] });
    await new SiteDeploy(fake.tools).waitForStaging(GATE);
    expect(fake.fetched).toEqual([[`${STATUSES_URL}?per_page=100`, 'GET']]);
    expect(fake.requestHeaders[0].authorization).toBe('Bearer github-token');
  });

  test('keeps waiting while staging is pending, missing or on another zip', async () => {
    const fake = fakeTools({
      statusRounds: [
        [],
        [status('success', 'other check', 'ci/other')],
        [status('pending', '26.46.01 99682b0a0ca3')],
        [status('success', '26.46.01 000000000000')],
        [status('success', '26.46.01 99682b0a0ca3')],
      ],
    });
    await new SiteDeploy(fake.tools).waitForStaging(GATE);
    expect(fake.sleeps).toEqual([30, 30, 30, 30]);
  });

  test('stops at once when staging reports a failure', async () => {
    const fake = fakeTools({ statusRounds: [[status('failure', '26.46.01 99682b0a0ca3')]] });
    await expect(new SiteDeploy(fake.tools).waitForStaging(GATE)).rejects.toThrow('Staging on Floci reported failure');
    expect(fake.sleeps).toEqual([]);
  });

  test('stops at once when staging reports an error', async () => {
    const fake = fakeTools({ statusRounds: [[status('error', 'probe timed out')]] });
    await expect(new SiteDeploy(fake.tools).waitForStaging(GATE)).rejects.toThrow('reported error: probe timed out');
  });

  test('fails closed after 20 minutes without a matching success', async () => {
    const fake = fakeTools({ statusRounds: Array(SiteDeploy.STAGING_ATTEMPTS).fill([status('pending', '26.46.01 99682b0a0ca3')]) });
    await expect(new SiteDeploy(fake.tools).waitForStaging(GATE)).rejects.toThrow('No site-staging/floci success "26.46.01 99682b0a0ca3" on abc123 in time');
    expect(fake.sleeps.reduce((total, seconds) => total + seconds, 0)).toBe(1200);
  });

  test('fails when the statuses cannot be read', async () => {
    const fake = fakeTools({ statusCode: 403 });
    await expect(new SiteDeploy(fake.tools).waitForStaging(GATE)).rejects.toThrow('Reading the commit statuses failed with HTTP 403');
  });
});

describe('SiteDeploy.checkHeaders', () => {
  test('accepts a policy whose folded value contains the required header', () => {
    const policy = "customHeaders:\n  - pattern: '**/*'\n    headers:\n      - key: X-Content-Type-Options\n        value: >-\n          nosniff\n";
    expect(() => new SiteDeploy(fakeTools({ policy }).tools).checkHeaders(CONFIG)).not.toThrow();
  });

  test('names the headers the live policy lacks', () => {
    expect(() => new SiteDeploy(fakeTools({ policy: '' }).tools).checkHeaders(CONFIG)).toThrow('x-content-type-options');
  });

  test('reads the policy with GetApp only', () => {
    const fake = fakeTools({ policy: 'x-content-type-options nosniff' });
    new SiteDeploy(fake.tools).checkHeaders(CONFIG);
    expect(fake.calls).toEqual([['aws', 'amplify', 'get-app', '--app-id', CONFIG.appId, '--region', 'ca-central-1', '--output', 'json']]);
  });
});

describe('SiteDeploy.deploy', () => {
  test('deploys to the production branch and waits until the job succeeds', async () => {
    const fake = fakeTools({ jobStates: ['RUNNING', 'SUCCEED'], pages: productionSite() });
    await new SiteDeploy(fake.tools).deploy(CONFIG, zipFile());
    expect(fake.calls.map((call) => call[2])).toEqual(['create-deployment', 'start-deployment', 'get-job', 'get-job']);
    expect(fake.calls[0]).toContain('production');
    expect(fake.calls[1]).toContain('7');
    expect(fake.fetched).toEqual([['https://upload.example/zip', 'PUT']]);
  });

  test('uses the Amplify branch named in the config for every call', async () => {
    const fake = fakeTools({ jobStates: ['SUCCEED'], pages: productionSite() });
    await new SiteDeploy(fake.tools).deploy({ ...CONFIG, branch: 'release' }, zipFile());
    expect(fake.calls.map((call) => call[call.indexOf('--branch-name') + 1])).toEqual(['release', 'release', 'release']);
    expect(fake.logs).toEqual(['Amplify release job 7: SUCCEED']);
  });

  test('fails before any AWS call when the config names no branch', async () => {
    const fake = fakeTools({ pages: productionSite() });
    await expect(new SiteDeploy(fake.tools).deploy({ ...CONFIG, branch: '' }, zipFile())).rejects.toThrow('names no Amplify branch');
    expect(fake.calls).toEqual([]);
  });

  test('fails when the Amplify job fails', async () => {
    const fake = fakeTools({ jobStates: ['FAILED'], pages: productionSite() });
    await expect(new SiteDeploy(fake.tools).deploy(CONFIG, zipFile())).rejects.toThrow('FAILED');
  });

  test('fails when the Amplify job never finishes', async () => {
    const fake = fakeTools({ jobStates: Array(SiteDeploy.JOB_ATTEMPTS).fill('RUNNING'), pages: productionSite() });
    await expect(new SiteDeploy(fake.tools).deploy(CONFIG, zipFile())).rejects.toThrow('did not finish');
  });

  test('fails before starting when the upload is refused', async () => {
    const fake = fakeTools({ pages: { 'https://upload.example/zip': { status: 403, body: '' } } });
    await expect(new SiteDeploy(fake.tools).deploy(CONFIG, zipFile())).rejects.toThrow('HTTP 403');
    expect(fake.calls.map((call) => call[2])).toEqual(['create-deployment']);
  });
});

describe('SiteDeploy.liveVersion', () => {
  test('reads the version production serves', async () => {
    expect(await new SiteDeploy(fakeTools({ pages: productionSite() }).tools).liveVersion(CONFIG)).toBe('26.46.01');
  });

  test('is empty when the site has no version file yet', async () => {
    expect(await new SiteDeploy(fakeTools().tools).liveVersion(CONFIG)).toBe('');
  });
});

describe('SiteDeploy.probe', () => {
  test('passes when the version, content, type and headers match', async () => {
    const fake = fakeTools({ pages: productionSite() });
    await new SiteDeploy(fake.tools).probe(CONFIG, '26.46.01');
    expect(fake.logs.at(-1)).toBe('https://site.example serves 26.46.01; 1 probes passed');
  });

  test('lists every failed check', async () => {
    const fake = fakeTools({
      pages: {
        'https://site.example/site-version.json': { body: '{"version":"26.46.01"}' },
        'https://site.example/': { body: 'Other', headers: { 'content-type': 'text/plain' } },
      },
    });
    await expect(new SiteDeploy(fake.tools).probe(CONFIG, '26.46.01')).rejects.toThrow(
      'Probes failed: / lacks "Welcome"; / has content type text/plain; / lacks header x-content-type-options',
    );
  });

  test('accepts any content type when the probe lists none', async () => {
    const config = { ...CONFIG, probes: [{ path: '/', contains: 'Welcome', contentTypes: [] }] };
    const fake = fakeTools({ pages: productionSite() });
    await new SiteDeploy(fake.tools).probe(config, '26.46.01');
    expect(fake.logs).toHaveLength(1);
  });

  test('fails when production never serves the new version', async () => {
    const fake = fakeTools({ pages: { 'https://site.example/site-version.json': { body: '{"version":"26.45.07"}' } } });
    await expect(new SiteDeploy(fake.tools).probe(CONFIG, '26.46.01')).rejects.toThrow('does not serve 26.46.01');
  });

  test('probes the production domain itself', () => {
    expect(new SiteDeploy(fakeTools().tools).origin(CONFIG)).toBe('https://site.example');
  });
});

describe('SiteDeploy.main', () => {
  test('package prints the zip checksum', async () => {
    const output = await printed(['package', siteDirectory(), '26.46.01', 'abc123', join(mkdtempSync(join(tmpdir(), 'site-zip-')), 's.zip')], fakeTools());
    expect(output).toMatch(/^[0-9a-f]{64}$/);
  });

  test('verify confirms a matching checksum', async () => {
    const file = zipFile();
    expect(await printed(['verify', file, new SiteDeploy(fakeTools().tools).checksum(file)], fakeTools())).toBe('verified');
  });

  test('wait-staging uses GITHUB_TOKEN from the environment', async () => {
    const fake = fakeTools({ statusRounds: [[status('success', '26.46.01 99682b0a0ca3')]] });
    expect(await printed(['wait-staging', 'd31ma/SITE', 'abc123', '26.46.01', SHA256], fake, { GITHUB_TOKEN: 'from-env' })).toBe('staging passed');
    expect(fake.requestHeaders[0].authorization).toBe('Bearer from-env');
  });

  test('check-headers reads the config file', async () => {
    expect(await printed(['check-headers', configFile()], fakeTools({ policy: 'x-content-type-options: nosniff' }))).toBe('header policy covers the required headers');
  });

  test('deploy runs the Amplify deployment', async () => {
    expect(await printed(['deploy', configFile(), zipFile()], fakeTools({ jobStates: ['SUCCEED'], pages: productionSite() }))).toBe('deployed');
  });

  test('live-version prints the served version', async () => {
    expect(await printed(['live-version', configFile()], fakeTools({ pages: productionSite() }))).toBe('26.46.01');
  });

  test('probe reports the probes passed', async () => {
    expect(await printed(['probe', configFile(), '26.46.01'], fakeTools({ pages: productionSite() }))).toBe('probes passed');
  });

  test('an unknown command prints the usage', async () => {
    await expect(SiteDeploy.main(['publish'], new SiteDeploy(fakeTools().tools), {})).rejects.toThrow('Usage');
  });
});

describe('SiteDeploy.run', () => {
  test('returns the standard output of a command', () => {
    expect(SiteDeploy.run('printf', ['ready'])).toBe('ready');
  });

  test('fails when the command fails', () => {
    expect(() => SiteDeploy.run('false', [])).toThrow('false failed');
  });

  test('live tools are wired to the real process', () => {
    expect(SiteDeploy.live().tools.run).toBe(SiteDeploy.run);
  });
});
