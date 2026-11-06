const assert = require('node:assert/strict');
const { test } = require('node:test');

const { appendLog, getErrorType } = require('../out/logging.js');

function captureChannel() {
    const lines = [];
    return {
        lines,
        appendLine(line) {
            lines.push(line);
        }
    };
}

test('writes normalized UTC JSON events with only supported fields', () => {
    const channel = captureChannel();
    appendLog(channel, 'error', 'lsp.start.failed', 'lsp.start', 'Language server failed', {
        outcome: 'failure',
        durationMs: 12.5,
        errorType: 'SpawnError',
        secret: 'must not be included'
    });

    assert.equal(channel.lines.length, 1);
    const event = JSON.parse(channel.lines[0]);
    assert.match(event.timestamp, /^\d{4}-\d\d-\d\dT.*Z$/);
    assert.equal(event.level, 'error');
    assert.equal(event.service, 'yaraast');
    assert.equal(event.component, 'vscode-yaraast');
    assert.equal(event.event_name, 'lsp.start.failed');
    assert.equal(event.operation, 'lsp.start');
    assert.equal(event.outcome, 'failure');
    assert.equal(event.duration_ms, 12.5);
    assert.equal(event.error_type, 'SpawnError');
    assert.equal('secret' in event, false);
});

test('redacts credentials and control characters before writing one line', () => {
    const channel = captureChannel();
    appendLog(
        channel,
        'warn',
        'extension.diagnostic',
        'extension.diagnose',
        'api_key=hidden\nBearer hidden-token\rforged event',
        { errorType: 'Authorization: Bearer hidden-token' }
    );

    assert.equal(channel.lines.length, 1);
    assert.equal(channel.lines[0].includes('hidden-token'), false);
    assert.equal(channel.lines[0].includes('api_key=hidden'), false);
    assert.equal(channel.lines[0].includes('\n'), false);
    assert.equal(JSON.parse(channel.lines[0]).error_type, '[REDACTED AUTHORIZATION HEADER]');
});

test('does not throw if the output channel fails', () => {
    const channel = { appendLine() { throw new Error('destination failed'); } };
    assert.doesNotThrow(() => appendLog(channel, 'info', 'extension.started', 'extension.activate', 'Extension activated'));
});

test('does not use thrown values as log text', () => {
    assert.equal(getErrorType(new Error('token=secret')), 'Error');
    assert.equal(getErrorType('password=secret'), 'NonErrorThrown');
});

test('redacts cookie values, private keys, and oversized messages', () => {
    const channel = captureChannel();
    appendLog(
        channel,
        'error',
        'extension.failure',
        'extension.operation',
        'Cookie: session=hidden\n-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
    );
    appendLog(channel, 'warn', 'extension.large', 'extension.operation', 'x'.repeat(8193));

    assert.equal(channel.lines.length, 2);
    assert.equal(channel.lines[0].includes('session=hidden'), false);
    assert.equal(channel.lines[0].includes('-----BEGIN PRIVATE KEY-----'), false);
    assert.equal(JSON.parse(channel.lines[1]).message, '[REDACTED: log value exceeded size limit]');
});

test('keeps concurrent events distinct and valid', async () => {
    const channel = captureChannel();
    await Promise.all(Array.from({ length: 64 }, (_, index) => Promise.resolve().then(() => {
        appendLog(channel, 'debug', 'extension.concurrent', `operation.${index}`, 'Concurrent operation');
    })));

    const events = channel.lines.map((line) => JSON.parse(line));
    assert.equal(events.length, 64);
    assert.equal(new Set(events.map((event) => event.operation)).size, 64);
});

test('records extension lifecycle and command failures without leaking error messages', async () => {
    const Module = require('node:module');
    const originalLoad = Module._load;
    const channels = [];
    const commands = new Map();
    const vscode = {
        commands: {
            registerCommand(name, handler) {
                commands.set(name, handler);
                return { dispose() {} };
            },
            executeCommand() {
                return Promise.reject(new Error('token=private-value'));
            }
        },
        workspace: {
            getConfiguration() {
                return {
                    get: (name, fallback) => name === 'yaraast.lsp.enabled' ? false : fallback,
                    update: async () => {}
                };
            },
            onDidChangeConfiguration() {
                return { dispose() {} };
            },
            createFileSystemWatcher() {
                return { dispose() {} };
            }
        },
        window: {
            createOutputChannel() {
                const channel = captureChannel();
                channels.push(channel);
                return { ...channel, show() {}, dispose() {} };
            },
            showInformationMessage: async () => undefined,
            showErrorMessage: async () => undefined
        },
        env: { clipboard: { writeText: async () => {} } },
        Uri: { joinPath: (...parts) => parts.join('/') }
    };
    const languageClient = {
        LanguageClient: class {},
        RevealOutputChannelOn: { Never: 0 },
        TransportKind: { stdio: 0 }
    };
    const extensionPath = require.resolve('../out/extension.js');

    Module._load = function load(request, parent, isMain) {
        if (request === 'vscode') return vscode;
        if (request === 'vscode-languageclient/node') return languageClient;
        return originalLoad.call(this, request, parent, isMain);
    };

    try {
        delete require.cache[extensionPath];
        const extension = require(extensionPath);
        extension.activate({ subscriptions: [] });
        await new Promise((resolve) => setImmediate(resolve));
        await assert.rejects(commands.get('yaraast.openSettings')(), /token=private-value/);
        await extension.deactivate();

        const events = channels.flatMap((channel) => channel.lines.map((line) => JSON.parse(line)));
        assert.ok(events.some((event) => event.event_name === 'extension.activated'));
        assert.ok(events.some((event) => event.event_name === 'lsp.server.disabled'));
        assert.ok(events.some((event) => event.event_name === 'extension.operation.failed' && event.error_type === 'Error'));
        assert.ok(events.some((event) => event.event_name === 'extension.deactivated'));
        assert.equal(JSON.stringify(events).includes('private-value'), false);
    } finally {
        Module._load = originalLoad;
        delete require.cache[extensionPath];
    }
});
