/**
 * YARAAST VSCode Extension
 * Provides language support for YARA rules using the YARAAST Language Server
 */

import * as path from 'path';
import { workspace, ExtensionContext, window, commands } from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
    Executable
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

export function activate(context: ExtensionContext): void {
    console.log('YARAAST extension is now active');

    // Register commands
    context.subscriptions.push(
        commands.registerCommand('yaraast.restartServer', async () => {
            await restartServer();
        })
    );

    context.subscriptions.push(
        commands.registerCommand('yaraast.showOutputChannel', () => {
            client?.outputChannel.show();
        })
    );

    // Start the language server
    startLanguageServer(context);
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}

async function startLanguageServer(context: ExtensionContext): Promise<void> {
    const config = workspace.getConfiguration('yaraast.lsp');

    if (!config.get<boolean>('enabled')) {
        window.showInformationMessage('YARAAST Language Server is disabled');
        return;
    }

    // Get Python path from configuration
    const pythonPath = config.get<string>('pythonPath') || 'python';

    // Server options: use yaraast lsp command
    const serverOptions: ServerOptions = {
        command: pythonPath,
        args: ['-m', 'yaraast', 'lsp', '--stdio'],
        transport: TransportKind.stdio
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'yara' },
            { scheme: 'untitled', language: 'yara' }
        ],
        synchronize: {
            fileEvents: workspace.createFileSystemWatcher('**/*.{yar,yara}')
        },
        outputChannelName: 'YARAAST Language Server',
        traceOutputChannel: window.createOutputChannel('YARAAST LSP Trace'),
    };

    // Create the language client
    client = new LanguageClient(
        'yaraast',
        'YARAAST Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client (this will also start the server)
    try {
        await client.start();
        window.showInformationMessage('YARAAST Language Server started successfully');
    } catch (error) {
        window.showErrorMessage(
            `Failed to start YARAAST Language Server: ${error}\n\n` +
            `Make sure yaraast is installed with LSP support:\n` +
            `pip install 'yaraast[lsp]'`
        );
        throw error;
    }
}

async function restartServer(): Promise<void> {
    if (client) {
        await client.stop();
        client = undefined;
    }

    // Get the extension context (we'll need to store it)
    const config = workspace.getConfiguration('yaraast.lsp');

    if (!config.get<boolean>('enabled')) {
        window.showWarningMessage('YARAAST Language Server is disabled in settings');
        return;
    }

    // Restart (note: in production, you'd want to store the context)
    window.showInformationMessage('Restarting YARAAST Language Server...');

    // TODO: Store context globally to allow restart
    // For now, user should reload window
    window.showInformationMessage(
        'Please reload the window to restart the language server',
        'Reload Window'
    ).then(selection => {
        if (selection === 'Reload Window') {
            commands.executeCommand('workbench.action.reloadWindow');
        }
    });
}
