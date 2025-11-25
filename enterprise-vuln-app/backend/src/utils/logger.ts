/**
 * Vulnerable Logging Utility
 * 
 * Intentionally logs sensitive information for security testing
 * Contains information disclosure vulnerabilities
 */

import winston from 'winston';
import path from 'path';

// Create logs directory if it doesn't exist
import fs from 'fs';
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format that includes sensitive information
const vulnerableFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }), // Include full stack traces
    winston.format.json(),
    winston.format.printf((info) => {
        const log: any = {
            timestamp: info.timestamp,
            level: info.level,
            message: info.message,
            // Intentionally include sensitive data
            stack: info.stack,
            metadata: info.metadata || {}
        };

        // Include process information (information disclosure)
        if (process.env.LOG_SYSTEM_INFO !== 'false') {
            log.system = {
                pid: process.pid,
                platform: process.platform,
                nodeVersion: process.version,
                memory: process.memoryUsage(),
                uptime: process.uptime(),
                cwd: process.cwd(),
                execPath: process.execPath,
                argv: process.argv,
                env: process.env // VULNERABLE: Logs entire environment
            };
        }

        return JSON.stringify(log, null, 2);
    })
);

// Create logger with vulnerable configuration
export const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'debug',
    format: vulnerableFormat,
    defaultMeta: { service: 'vulncorp-enterprise' },
    transports: [
        // Console output with colors
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple(),
                winston.format.printf((info) => {
                    const { timestamp, level, message, stack, ...meta } = info;
                    let log = `${timestamp} [${level}] ${message}`;
                    
                    // Include metadata if present
                    if (Object.keys(meta).length > 0) {
                        log += `\\nMetadata: ${JSON.stringify(meta, null, 2)}`;
                    }
                    
                    // Include stack trace if present
                    if (stack) {
                        log += `\\nStack: ${stack}`;
                    }
                    
                    return log;
                })
            )
        }),

        // File transport for all logs
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 50 * 1024 * 1024, // 50MB
            maxFiles: 10,
            tailable: true
        }),

        // Error log file
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5,
            tailable: true
        }),

        // Security events log (vulnerable)
        new winston.transports.File({
            filename: path.join(logsDir, 'security.log'),
            level: 'warn',
            maxsize: 25 * 1024 * 1024, // 25MB
            maxFiles: 10,
            tailable: true
        })
    ],

    // Exception and rejection handling
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log')
        })
    ],
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log')
        })
    ],

    // Don't exit on handled exceptions (vulnerable)
    exitOnError: false
});

// Enhanced logging methods with vulnerability features
export const securityLogger = {
    // Log authentication events with sensitive data
    logAuth: (event: string, user: any, request: any, success: boolean = true) => {
        logger.warn('Authentication Event', {
            event,
            success,
            user: {
                id: user?.id,
                username: user?.username,
                email: user?.email,
                password: user?.password, // VULNERABLE: Log passwords
                role: user?.role,
                apiKey: user?.apiKey // VULNERABLE: Log API keys
            },
            request: {
                ip: request?.ip || request?.connection?.remoteAddress,
                userAgent: request?.get?.('User-Agent'),
                method: request?.method,
                url: request?.url,
                headers: request?.headers, // VULNERABLE: Log all headers
                body: request?.body, // VULNERABLE: Log request body
                params: request?.params,
                query: request?.query,
                sessionID: request?.sessionID,
                session: request?.session // VULNERABLE: Log session data
            }
        });
    },

    // Log database queries (SQL injection detection)
    logQuery: (query: string, params: any[], result: any, executionTime: number) => {
        logger.info('Database Query', {
            query, // VULNERABLE: Log raw SQL queries
            params, // VULNERABLE: Log parameters
            resultCount: Array.isArray(result) ? result.length : 1,
            executionTime,
            sensitive: {
                fullResult: result, // VULNERABLE: Log complete results
                connectionInfo: {
                    host: process.env.DB_HOST,
                    user: process.env.DB_USER,
                    database: process.env.DB_NAME
                }
            }
        });
    },

    // Log file operations
    logFile: (operation: string, filename: string, user: any, success: boolean = true) => {
        logger.info('File Operation', {
            operation,
            filename,
            success,
            user: {
                id: user?.id,
                username: user?.username,
                role: user?.role
            },
            fileInfo: {
                fullPath: path.resolve(filename), // VULNERABLE: Log full paths
                exists: fs.existsSync(filename),
                stats: fs.existsSync(filename) ? fs.statSync(filename) : null
            }
        });
    },

    // Log API requests with full details
    logAPI: (req: any, res: any, responseTime: number) => {
        logger.info('API Request', {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            responseTime,
            // VULNERABLE: Log sensitive request details
            headers: req.headers,
            body: req.body,
            query: req.query,
            params: req.params,
            user: req.user,
            session: req.session,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            referer: req.get('Referer'),
            // Response data
            responseHeaders: res.getHeaders(),
            responseSize: res.get('Content-Length') || 0
        });
    },

    // Log errors with full stack traces and context
    logError: (error: Error, context: any = {}) => {
        logger.error('Application Error', {
            error: {
                name: error.name,
                message: error.message,
                stack: error.stack, // VULNERABLE: Full stack traces
                code: (error as any).code,
                errno: (error as any).errno,
                syscall: (error as any).syscall,
                path: (error as any).path
            },
            context: {
                ...context,
                // VULNERABLE: Include environment details
                environment: process.env,
                processInfo: {
                    pid: process.pid,
                    ppid: process.ppid,
                    platform: process.platform,
                    arch: process.arch,
                    version: process.version,
                    versions: process.versions,
                    execPath: process.execPath,
                    execArgv: process.execArgv,
                    argv: process.argv,
                    cwd: process.cwd(),
                    uptime: process.uptime(),
                    memory: process.memoryUsage(),
                    cpuUsage: process.cpuUsage()
                }
            }
        });
    }
};

// Request logging middleware
export const requestLogger = (req: any, res: any, next: any) => {
    const startTime = Date.now();
    
    // Log request details
    logger.debug('Incoming Request', {
        method: req.method,
        url: req.originalUrl,
        headers: req.headers, // VULNERABLE: Log all headers
        body: req.body, // VULNERABLE: Log request body
        query: req.query,
        params: req.params,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionID: req.sessionID,
        timestamp: new Date().toISOString()
    });

    // Override res.json to log response data
    const originalJson = res.json;
    res.json = function(body: any) {
        const responseTime = Date.now() - startTime;
        
        // Log response details
        logger.debug('Outgoing Response', {
            statusCode: res.statusCode,
            responseTime,
            body, // VULNERABLE: Log response body
            headers: res.getHeaders(),
            size: JSON.stringify(body).length
        });
        
        return originalJson.call(this, body);
    };

    next();
};

export default logger;

