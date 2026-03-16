/**
 * YARAAST VSCode Extension
 * Provides language support for YARA rules using the YARAAST Language Server
 */

import { spawnSync } from 'child_process';
import {
    commands,
    ConfigurationChangeEvent,
    env,
    ExtensionContext,
    OutputChannel,
    QuickPickItem,
    Uri,
    window,
    workspace
} from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    RevealOutputChannelOn,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let extensionContextRef: ExtensionContext | undefined;
let outputChannel: OutputChannel | undefined;
let traceChannel: OutputChannel | undefined;

type RuntimeSettings = {
    cacheWorkspace: boolean;
    dialectMode: string;
    codeFormatting: {
        indent_size: number;
        brace_style: string;
        sort_meta: boolean;
        sort_strings: boolean;
    };
};

export function activate(context: ExtensionContext): void {
    extensionContextRef = context;
    outputChannel = window.createOutputChannel('YARAAST Language Server');
    traceChannel = window.createOutputChannel('YARAAST LSP Trace');

    context.subscriptions.push(outputChannel, traceChannel);

    context.subscriptions.push(
        commands.registerCommand('yaraast.restartServer', async () => {
            await restartServer();
        }),
        commands.registerCommand('yaraast.showOutputChannel', () => {
            outputChannel?.show(true);
        }),
        commands.registerCommand('yaraast.showServerInfo', () => {
            const config = getExtensionConfig();
            const runtime = buildRuntimeSettings();
            const message = [
                `python: ${config.pythonPath}`,
                `module: ${config.serverModule}`,
                `dialect: ${runtime.dialectMode}`,
                `cacheWorkspace: ${runtime.cacheWorkspace}`,
                `formatting: ${JSON.stringify(runtime.codeFormatting)}`
            ].join('\n');
            outputChannel?.appendLine('[info] current server configuration');
            outputChannel?.appendLine(message);
            outputChannel?.show(true);
            void window.showInformationMessage('YARAAST server configuration written to Output Channel');
        }),
        commands.registerCommand('yaraast.selectDialectMode', async () => {
            await selectDialectMode();
        }),
        commands.registerCommand('yaraast.toggleServer', async () => {
            await toggleServer();
        }),
        commands.registerCommand('yaraast.diagnoseServer', async () => {
            await diagnoseServerEnvironment();
        }),
        commands.registerCommand('yaraast.openSettings', async () => {
            await commands.executeCommand('workbench.action.openSettings', '@ext:seifreed.yaraast');
        }),
        commands.registerCommand('yaraast.showServerStatus', async () => {
            await showServerStatus();
        }),
        commands.registerCommand('yaraast.copyServerStatus', async () => {
            await copyServerStatus();
        }),
        commands.registerCommand('yaraast.showRuntimeMetrics', async () => {
            await showRuntimeMetrics();
        }),
        commands.registerCommand('yaraast.openRuntimeDashboard', async () => {
            await openRuntimeDashboard();
        }),
        commands.registerCommand('yaraast.previewRefactors', async () => {
            await previewRefactors();
        }),
        workspace.onDidChangeConfiguration(async (event) => {
            await handleConfigurationChange(event);
        })
    );

    void startLanguageServer(context);
}

export function deactivate(): Thenable<void> | undefined {
    return stopLanguageServer();
}

async function startLanguageServer(context: ExtensionContext): Promise<void> {
    const config = getExtensionConfig();

    if (!config.enabled) {
        outputChannel?.appendLine('[info] language server disabled by configuration');
        return;
    }

    const environmentError = checkServerEnvironment(config.pythonPath, config.serverModule);
    if (environmentError) {
        outputChannel?.appendLine(`[error] ${environmentError}`);
        void showEnvironmentFailure(environmentError);
        return;
    }

    const runtimeSettings = buildRuntimeSettings();
    const serverOptions: ServerOptions = {
        command: config.pythonPath,
        args: ['-m', config.serverModule, 'lsp', '--stdio'],
        transport: TransportKind.stdio
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'yara' },
            { scheme: 'untitled', language: 'yara' }
        ],
        synchronize: {
            configurationSection: ['yaraast.lsp', 'yaraast.formatting', 'yaraast.diagnostics'],
            fileEvents: workspace.createFileSystemWatcher('**/*.{yar,yara}')
        },
        initializationOptions: runtimeSettings,
        outputChannel,
        traceOutputChannel: traceChannel,
        outputChannelName: 'YARAAST Language Server',
        revealOutputChannelOn: RevealOutputChannelOn.Never
    };

    client = new LanguageClient(
        'yaraast',
        'YARAAST Language Server',
        serverOptions,
        clientOptions
    );

    try {
        await client.start();
        outputChannel?.appendLine('[info] language server started successfully');
        await pushRuntimeSettings();
    } catch (error) {
        outputChannel?.appendLine(`[error] failed to start language server: ${String(error)}`);
        void window.showErrorMessage(
            `Failed to start YARAAST Language Server: ${error}\n\n` +
            `Make sure yaraast is installed with LSP support:\n` +
            `pip install 'yaraast[lsp]'`
        );
        throw error;
    }
}

async function stopLanguageServer(): Promise<void> {
    if (!client) {
        return;
    }
    const current = client;
    client = undefined;
    await current.stop();
}

async function restartServer(): Promise<void> {
    if (!extensionContextRef) {
        void window.showErrorMessage('Extension context is not available yet');
        return;
    }

    outputChannel?.appendLine('[info] restarting language server');
    await stopLanguageServer();
    await startLanguageServer(extensionContextRef);
    void window.showInformationMessage('YARAAST Language Server restarted');
}

async function selectDialectMode(): Promise<void> {
    const items: Array<QuickPickItem & { value: string }> = [
        { label: 'Auto', description: 'Detect dialect automatically', value: 'auto' },
        { label: 'YARA', description: 'Force classic YARA mode', value: 'yara' },
        { label: 'YARA-L', description: 'Force YARA-L mode', value: 'yaral' },
        { label: 'YARA-X', description: 'Force YARA-X mode', value: 'yarax' }
    ];
    const selected = await window.showQuickPick(items, {
        placeHolder: 'Select the dialect mode for the YARAAST language server'
    });
    if (!selected) {
        return;
    }
    await workspace.getConfiguration().update('yaraast.lsp.dialectMode', selected.value, true);
    outputChannel?.appendLine(`[info] dialect mode set to ${selected.value}`);
    void window.showInformationMessage(`YARAAST dialect mode set to ${selected.label}`);
}

async function toggleServer(): Promise<void> {
    const config = workspace.getConfiguration();
    const current = config.get<boolean>('yaraast.lsp.enabled', true);
    await config.update('yaraast.lsp.enabled', !current, true);
    outputChannel?.appendLine(`[info] language server ${!current ? 'enabled' : 'disabled'}`);
    void window.showInformationMessage(`YARAAST language server ${!current ? 'enabled' : 'disabled'}`);
}

async function showServerStatus(): Promise<void> {
    const config = getExtensionConfig();
    const runtime = buildRuntimeSettings();
    const environmentError = checkServerEnvironment(config.pythonPath, config.serverModule);
    const remoteStatus = await fetchRuntimeStatus();
    const status = [
        `enabled: ${config.enabled}`,
        `running: ${Boolean(client)}`,
        `python: ${config.pythonPath}`,
        `module: ${config.serverModule}`,
        `dialect: ${runtime.dialectMode}`,
        `cacheWorkspace: ${runtime.cacheWorkspace}`,
        `environment: ${environmentError ? 'invalid' : 'ok'}`,
        'runtime_status:',
        indentStatus(formatRuntimeStatus(remoteStatus))
    ].join('\n');
    outputChannel?.appendLine('[info] server status');
    outputChannel?.appendLine(status);
    if (environmentError) {
        outputChannel?.appendLine(`[error] ${environmentError}`);
    }
    outputChannel?.show(true);
    if (remoteStatus) {
        await openRuntimeDashboard(remoteStatus);
        return;
    }
    void window.showInformationMessage('YARAAST server status written to Output Channel');
}

async function copyServerStatus(): Promise<void> {
    const config = getExtensionConfig();
    const runtime = buildRuntimeSettings();
    const environmentError = checkServerEnvironment(config.pythonPath, config.serverModule);
    const remoteStatus = await fetchRuntimeStatus();
    const status = [
        `enabled: ${config.enabled}`,
        `running: ${Boolean(client)}`,
        `python: ${config.pythonPath}`,
        `module: ${config.serverModule}`,
        `dialect: ${runtime.dialectMode}`,
        `cacheWorkspace: ${runtime.cacheWorkspace}`,
        `environment: ${environmentError ? 'invalid' : 'ok'}`,
        'runtime_status:',
        indentStatus(formatRuntimeStatus(remoteStatus))
    ].join('\n');
    await env.clipboard.writeText(status);
    void window.showInformationMessage('YARAAST server status copied to clipboard');
}

async function showRuntimeMetrics(): Promise<void> {
    const remoteStatus = await fetchRuntimeStatus();
    const latency = remoteStatus?.latency ?? {};
    const keys = Object.keys(latency).sort();
    if (keys.length === 0) {
        void window.showInformationMessage('No YARAAST runtime metrics available');
        return;
    }
    const lines = keys.map((key) => {
        const metric = latency[key];
        return `${key}: avg=${metric.avg_ms?.toFixed?.(2) ?? metric.avg_ms}ms max=${metric.max_ms?.toFixed?.(2) ?? metric.max_ms}ms count=${metric.count ?? 0}`;
    });
    outputChannel?.appendLine('[info] runtime metrics');
    outputChannel?.appendLine(lines.join('\n'));
    outputChannel?.show(true);
    await openRuntimeDashboard(remoteStatus);
}

async function openRuntimeDashboard(remoteStatus?: any | null): Promise<void> {
    const status = remoteStatus ?? await fetchRuntimeStatus();
    const panel = window.createWebviewPanel(
        'yaraastRuntimeDashboard',
        'YARAAST Runtime Dashboard',
        { preserveFocus: true, viewColumn: 2 },
        {}
    );
    panel.webview.html = renderRuntimeDashboard(status);
}

async function previewRefactors(): Promise<void> {
    const editor = window.activeTextEditor;
    if (!editor) {
        void window.showInformationMessage('No active editor');
        return;
    }

    const actions = await commands.executeCommand<any[]>(
        'vscode.executeCodeActionProvider',
        editor.document.uri,
        editor.selection
    );
    if (!actions || actions.length === 0) {
        void window.showInformationMessage('No refactors available for the current selection');
        return;
    }

    const refactors = actions
        .filter((action) => action?.kind?.value?.startsWith?.('refactor') || action?.kind?.startsWith?.('refactor'))
        .map((action) => ({
            label: action.title,
            description: action.data?.preview ?? 'No preview available',
            action,
        }));

    if (refactors.length === 0) {
        void window.showInformationMessage('No refactor previews available for the current selection');
        return;
    }

    const selected = await window.showQuickPick(refactors, {
        placeHolder: 'Available YARAAST refactors',
        matchOnDescription: true,
    });
    if (!selected) {
        return;
    }

    if (selected.action.edit) {
        await workspace.applyEdit(selected.action.edit);
    }
    if (selected.action.command) {
        await commands.executeCommand(
            selected.action.command.command,
            ...(selected.action.command.arguments ?? [])
        );
    }
    void window.showInformationMessage(`Applied refactor: ${selected.label}`);
}

function indentStatus(status: string | null): string {
    if (!status) {
        return '  unavailable';
    }
    return status.split('\n').map((line) => `  ${line}`).join('\n');
}

function formatRuntimeStatus(status: any | null): string | null {
    if (!status) {
        return null;
    }
    const lines = [
        `open_documents: ${status.open_documents ?? 0}`,
        `cached_documents: ${status.cached_documents ?? 0}`,
        `workspace_symbols: ${status.workspace_symbols ?? 0}`,
        `dirty_documents: ${status.dirty_documents ?? 0}`,
        `language_mode: ${status.language_mode ?? 'unknown'}`,
        `cache_workspace: ${status.cache_workspace ?? false}`,
    ];
    const workspaceFolders = Array.isArray(status.workspace_folders) ? status.workspace_folders : [];
    if (workspaceFolders.length > 0) {
        lines.push(`workspace_folders: ${workspaceFolders.join(', ')}`);
    }
    if (status.index_path) {
        lines.push(`index_path: ${status.index_path}`);
    }
    const latency = status.latency ?? {};
    const latencyKeys = Object.keys(latency);
    if (latencyKeys.length > 0) {
        lines.push('latency:');
        for (const key of latencyKeys.sort()) {
            const metric = latency[key];
            lines.push(
                `  ${key}: avg=${metric.avg_ms?.toFixed?.(2) ?? metric.avg_ms}ms max=${metric.max_ms?.toFixed?.(2) ?? metric.max_ms}ms count=${metric.count ?? 0}`
            );
        }
    }
    return lines.join('\n');
}

function renderRuntimeDashboard(status: any | null): string {
    const safe = status ?? {};
    const latency = safe.latency ?? {};
    const cacheStats = safe.cache_stats ?? {};
    const workspaceFolders = Array.isArray(safe.workspace_folders) ? safe.workspace_folders : [];
    const generatedAt = new Date().toLocaleString();
    const topLatency = Object.keys(latency)
        .sort((a, b) => (latency[b]?.avg_ms ?? 0) - (latency[a]?.avg_ms ?? 0))
        .slice(0, 3)
        .map((key) => `${key} (${latency[key]?.avg_ms ?? 0} ms)`)
        .join(', ');
    const topLatencyValue = Math.max(0, ...Object.keys(latency).map((key) => Number(latency[key]?.avg_ms ?? 0)));
    const health = topLatencyValue < 25 ? 'healthy' : topLatencyValue < 100 ? 'watch' : 'slow';
    const latencyRows = Object.keys(latency).sort().map((key) => {
        const metric = latency[key];
        return `<tr><td>${escapeHtml(String(key))}</td><td>${metric.avg_ms ?? 0}</td><td>${metric.max_ms ?? 0}</td><td>${metric.count ?? 0}</td></tr>`;
    }).join('');
    const cacheRows = Object.keys(cacheStats).sort().map((key) => {
        return `<tr><td>${escapeHtml(String(key))}</td><td>${cacheStats[key]}</td></tr>`;
    }).join('');
    const cacheCards = [
        ['Workspace generation', cacheStats.workspace_generation ?? 0],
        ['Workspace symbol queries', cacheStats.workspace_symbol_queries ?? 0],
        ['Rule definition cache', cacheStats.rule_definition_entries ?? 0],
        ['Rule references cache', cacheStats.rule_reference_entries ?? 0],
        ['Rule link cache', cacheStats.rule_reference_record_entries ?? 0],
        ['Document analysis cache', cacheStats.document_analysis_entries ?? 0],
    ].map(([label, value]) => `<div class="card"><div class="label">${escapeHtml(String(label))}</div><div class="value">${escapeHtml(String(value))}</div></div>`).join('');
    const cards = [
        ['Open documents', safe.open_documents ?? 0],
        ['Cached documents', safe.cached_documents ?? 0],
        ['Workspace symbols', safe.workspace_symbols ?? 0],
        ['Dirty documents', safe.dirty_documents ?? 0],
    ].map(([label, value]) => `<div class="card"><div class="label">${escapeHtml(String(label))}</div><div class="value">${escapeHtml(String(value))}</div></div>`).join('');
    const folderList = workspaceFolders.length > 0
        ? `<ul>${workspaceFolders.map((folder: string) => `<li>${escapeHtml(folder)}</li>`).join('')}</ul>`
        : '<p>No workspace folders</p>';
    return `<!doctype html>
<html>
  <head>
    <style>
      :root { color-scheme: light dark; }
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 20px; line-height: 1.45; }
      h1, h2 { margin: 0 0 12px; }
      h2 { margin-top: 24px; }
      .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0 24px; }
      .card { border: 1px solid rgba(127,127,127,0.35); border-radius: 10px; padding: 14px; background: rgba(127,127,127,0.08); }
      .label { font-size: 12px; opacity: 0.75; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.04em; }
      .value { font-size: 24px; font-weight: 700; }
      .muted { opacity: 0.75; margin-top: -4px; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid rgba(127,127,127,0.35); padding: 8px 10px; text-align: left; }
      th { background: rgba(127,127,127,0.12); }
      pre { border: 1px solid rgba(127,127,127,0.35); border-radius: 10px; padding: 12px; background: rgba(127,127,127,0.08); overflow: auto; }
      ul { padding-left: 20px; }
    </style>
  </head>
  <body>
    <h1>YARAAST Runtime Dashboard</h1>
    <div class="muted">Updated: ${escapeHtml(generatedAt)}</div>
    <div class="cards">${cards}</div>
    <h2>Summary</h2>
    <pre>${escapeHtml([
        `language_mode: ${safe.language_mode ?? 'unknown'}`,
        `health: ${health}`,
        `cache_workspace: ${safe.cache_workspace ?? false}`,
        `workspace_generation: ${cacheStats.workspace_generation ?? 0}`,
        `top_latency: ${topLatency || 'n/a'}`
    ].join('\n'))}</pre>
    <h2>Status</h2>
    <pre>${escapeHtml(formatRuntimeStatus(safe) ?? 'unavailable')}</pre>
    <h2>Workspace Folders</h2>
    ${folderList}
    <h2>Latency</h2>
    <table>
      <thead><tr><th>operation</th><th>avg_ms</th><th>max_ms</th><th>count</th></tr></thead>
      <tbody>${latencyRows || '<tr><td colspan="4">No metrics</td></tr>'}</tbody>
    </table>
    <h2>Cache Summary</h2>
    <div class="cards">${cacheCards}</div>
    <h2>Cache Stats</h2>
    <table>
      <thead><tr><th>key</th><th>value</th></tr></thead>
      <tbody>${cacheRows || '<tr><td colspan="2">No cache stats</td></tr>'}</tbody>
    </table>
  </body>
</html>`;
}

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

async function fetchRuntimeStatus(): Promise<any | null> {
    if (!client) {
        return null;
    }
    try {
        return await client.sendRequest('yaraast/status');
    } catch {
        return null;
    }
}

async function handleConfigurationChange(event: ConfigurationChangeEvent): Promise<void> {
    const requiresRestart =
        event.affectsConfiguration('yaraast.lsp.enabled') ||
        event.affectsConfiguration('yaraast.lsp.pythonPath') ||
        event.affectsConfiguration('yaraast.lsp.serverModule');

    if (requiresRestart) {
        await restartServer();
        return;
    }

    const requiresPush =
        event.affectsConfiguration('yaraast.lsp.dialectMode') ||
        event.affectsConfiguration('yaraast.lsp.cacheWorkspace') ||
        event.affectsConfiguration('yaraast.formatting.style') ||
        event.affectsConfiguration('yaraast.formatting.indentSize') ||
        event.affectsConfiguration('yaraast.formatting.braceStyle') ||
        event.affectsConfiguration('yaraast.formatting.sortMeta') ||
        event.affectsConfiguration('yaraast.formatting.sortStrings');

    if (requiresPush) {
        await pushRuntimeSettings();
    }
}

async function pushRuntimeSettings(): Promise<void> {
    if (!client) {
        return;
    }
    const settings = buildRuntimeSettings();
    outputChannel?.appendLine(`[info] updating runtime settings: ${JSON.stringify(settings)}`);
    await client.sendNotification('workspace/didChangeConfiguration', { settings });
}

function getExtensionConfig(): {
    enabled: boolean;
    pythonPath: string;
    serverModule: string;
} {
    const config = workspace.getConfiguration();
    return {
        enabled: config.get<boolean>('yaraast.lsp.enabled', true),
        pythonPath: config.get<string>('yaraast.lsp.pythonPath', 'python'),
        serverModule: config.get<string>('yaraast.lsp.serverModule', 'yaraast')
    };
}

function checkServerEnvironment(pythonPath: string, serverModule: string): string | null {
    const versionCheck = spawnSync(
        pythonPath,
        ['-m', serverModule, '--version'],
        { encoding: 'utf-8' }
    );

    if (versionCheck.error) {
        return `Unable to execute Python interpreter '${pythonPath}': ${versionCheck.error.message}`;
    }
    if (versionCheck.status !== 0) {
        return [
            `Unable to start '${pythonPath} -m ${serverModule}'.`,
            'Make sure yaraast is installed in that interpreter with LSP support:',
            `pip install 'yaraast[lsp]'`
        ].join('\n');
    }

    const lspCheck = spawnSync(
        pythonPath,
        ['-m', serverModule, 'lsp', '--help'],
        { encoding: 'utf-8' }
    );
    if (lspCheck.error || lspCheck.status !== 0) {
        return [
            `The module '${serverModule}' is installed, but 'lsp' is not available.`,
            `Check that '${pythonPath}' has yaraast with the LSP extra installed.`,
            `pip install 'yaraast[lsp]'`
        ].join('\n');
    }

    return null;
}

function buildEnvironmentReport(): string {
    const config = getExtensionConfig();
    const runtime = buildRuntimeSettings();
    const environmentError = checkServerEnvironment(config.pythonPath, config.serverModule);
    return [
        'YARAAST environment report',
        `enabled: ${config.enabled}`,
        `running: ${Boolean(client)}`,
        `python: ${config.pythonPath}`,
        `module: ${config.serverModule}`,
        `dialect: ${runtime.dialectMode}`,
        `cacheWorkspace: ${runtime.cacheWorkspace}`,
        `environment_ok: ${environmentError ? 'false' : 'true'}`,
        `environment_error: ${environmentError ?? 'none'}`
    ].join('\n');
}

async function diagnoseServerEnvironment(): Promise<void> {
    const report = buildEnvironmentReport();
    outputChannel?.appendLine('[info] environment diagnostics');
    outputChannel?.appendLine(report);
    outputChannel?.show(true);
    await env.clipboard.writeText(report);
    void window.showInformationMessage('YARAAST environment report copied to clipboard');
}

async function showEnvironmentFailure(message: string): Promise<void> {
    const selection = await window.showErrorMessage(
        message,
        'Show Output',
        'Copy Diagnostics',
        'Open Settings',
        'Open README'
    );
    if (selection === 'Show Output') {
        outputChannel?.show(true);
        return;
    }
    if (selection === 'Copy Diagnostics') {
        await diagnoseServerEnvironment();
        return;
    }
    if (selection === 'Open Settings') {
        await commands.executeCommand('workbench.action.openSettings', '@ext:seifreed.yaraast');
        return;
    }
    if (selection === 'Open README') {
        await commands.executeCommand(
            'vscode.open',
            Uri.joinPath(extensionContextRef!.extensionUri, 'README.md')
        );
    }
}

function buildRuntimeSettings(): RuntimeSettings {
    const config = workspace.getConfiguration();
    const formattingStyle = config.get<string>('yaraast.formatting.style', 'default');
    const indentSize = config.get<number>('yaraast.formatting.indentSize', 4);
    const braceStyle = config.get<string>('yaraast.formatting.braceStyle', 'same_line');
    const sortMeta = config.get<boolean>('yaraast.formatting.sortMeta', false);
    const sortStrings = config.get<boolean>('yaraast.formatting.sortStrings', false);

    const codeFormatting = {
        ...styleDefaults(formattingStyle),
        indent_size: indentSize,
        brace_style: braceStyle,
        sort_meta: sortMeta,
        sort_strings: sortStrings
    };

    return {
        cacheWorkspace: config.get<boolean>('yaraast.lsp.cacheWorkspace', true),
        dialectMode: config.get<string>('yaraast.lsp.dialectMode', 'auto'),
        codeFormatting
    };
}

function styleDefaults(style: string): RuntimeSettings['codeFormatting'] {
    if (style === 'compact') {
        return {
            indent_size: 2,
            brace_style: 'same_line',
            sort_meta: false,
            sort_strings: false
        };
    }
    if (style === 'verbose') {
        return {
            indent_size: 4,
            brace_style: 'new_line',
            sort_meta: true,
            sort_strings: true
        };
    }
    if (style === 'readable') {
        return {
            indent_size: 4,
            brace_style: 'same_line',
            sort_meta: false,
            sort_strings: false
        };
    }
    return {
        indent_size: 4,
        brace_style: 'same_line',
        sort_meta: false,
        sort_strings: false
    };
}
