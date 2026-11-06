"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getErrorType = getErrorType;
exports.appendLog = appendLog;
const secretAssignment = /\b(?:password|passwd|(?:access|refresh|id|auth)?[_-]?token|session[_-]?id|jwt|credentials?|(?:x-)?api[_-]?key|client[_-]?secret|private[_ -]?key|secret)\b["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi;
const authorizationHeader = /\b(?:authorization|proxy-authorization)\b["']?\s*[:=]\s*[^\r\n]*/gi;
const cookieHeader = /\b(?:cookie|set-cookie)\b["']?\s*[:=]\s*[^\r\n]*/gi;
const bearerToken = /\bBearer\s+\S+/gi;
const privateKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const controlCharacters = /\p{Cc}+/gu;
const maxLogText = 8192;
function safeText(value) {
    if (value.length > maxLogText) {
        return '[REDACTED: log value exceeded size limit]';
    }
    const redacted = value
        .replace(privateKey, '[REDACTED PRIVATE KEY]')
        .replace(authorizationHeader, '[REDACTED AUTHORIZATION HEADER]')
        .replace(cookieHeader, '[REDACTED COOKIE HEADER]')
        .replace(bearerToken, 'Bearer [REDACTED]')
        .replace(secretAssignment, '[REDACTED SECRET]')
        .replace(controlCharacters, ' ');
    return redacted.length <= maxLogText
        ? redacted
        : '[REDACTED: log value exceeded size limit]';
}
function getErrorType(error) {
    return safeText(error instanceof Error ? error.name || 'Error' : 'NonErrorThrown');
}
function appendLog(channel, level, eventName, operation, message, fields = {}) {
    if (!channel) {
        return;
    }
    const event = {
        timestamp: new Date().toISOString(),
        level,
        message: safeText(message),
        service: 'yaraast',
        component: 'vscode-yaraast',
        ['event_name']: safeText(eventName),
        operation: safeText(operation)
    };
    if (fields.outcome) {
        event.outcome = fields.outcome;
    }
    if (fields.durationMs !== undefined && Number.isFinite(fields.durationMs)) {
        event.duration_ms = Math.max(0, fields.durationMs);
    }
    if (fields.errorType) {
        event.error_type = safeText(fields.errorType);
    }
    if (fields.errorCode) {
        event.error_code = safeText(fields.errorCode);
    }
    try {
        channel.appendLine(JSON.stringify(event));
    }
    catch {
        // Logging is best-effort and must not interrupt the extension.
    }
}
//# sourceMappingURL=logging.js.map