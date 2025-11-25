/**
 * Database Configuration for VulnCorp Enterprise
 * 
 * Contains intentionally vulnerable database configurations
 * for comprehensive security testing
 */

export const config = {
    // MySQL Configuration (Primary database)
    mysql: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '3306'),
        user: process.env.DB_USER || 'vulnuser',
        password: process.env.DB_PASS || 'weakpassword',
        database: process.env.DB_NAME || 'vulncorp_enterprise',
        connectionLimit: 100,
        acquireTimeout: 60000,
        timeout: 60000,
        reconnect: true,
        // Intentionally vulnerable settings
        ssl: false, // No SSL encryption
        charset: 'utf8', // Allows certain injection techniques
        multipleStatements: true, // Allows multiple SQL statements (dangerous)
        supportBigNumbers: true,
        bigNumberStrings: true,
        dateStrings: true,
        timezone: 'local'
    },

    // Redis Configuration (Session storage & caching)
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        password: process.env.REDIS_PASS || undefined, // No password by default
        db: 0,
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null,
        lazyConnect: true,
        // Vulnerable settings
        family: 4, // IPv4
        keepAlive: false, // No connection keep-alive
        commandTimeout: 5000
    },

    // MongoDB Configuration (NoSQL injection testing)
    mongodb: {
        host: process.env.MONGODB_HOST || 'localhost',
        port: parseInt(process.env.MONGODB_PORT || '27017'),
        database: process.env.MONGODB_DB || 'vulncorp_nosql',
        username: process.env.MONGODB_USER || undefined,
        password: process.env.MONGODB_PASS || undefined,
        authSource: 'admin',
        // Intentionally vulnerable options
        useUnifiedTopology: true,
        useNewUrlParser: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferMaxEntries: 0,
        bufferCommands: false,
        // No authentication by default for testing
        auth: false
    },

    // PostgreSQL Configuration (Additional SQL testing)
    postgresql: {
        host: process.env.POSTGRES_HOST || 'localhost',
        port: parseInt(process.env.POSTGRES_PORT || '5432'),
        user: process.env.POSTGRES_USER || 'pguser',
        password: process.env.POSTGRES_PASS || 'weakpgpass',
        database: process.env.POSTGRES_DB || 'vulncorp_pg',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        // Vulnerable settings
        ssl: false,
        statement_timeout: false,
        query_timeout: false,
        application_name: 'vulncorp_enterprise'
    },

    // Elasticsearch Configuration (Search injection testing)
    elasticsearch: {
        host: process.env.ELASTICSEARCH_HOST || 'localhost',
        port: parseInt(process.env.ELASTICSEARCH_PORT || '9200'),
        protocol: 'http', // No HTTPS
        auth: undefined, // No authentication
        index: 'vulncorp',
        // Vulnerable settings
        sniffOnStart: false,
        sniffInterval: false,
        sniffOnConnectionFault: false,
        maxRetries: 3,
        requestTimeout: 30000,
        pingTimeout: 3000,
        log: 'error'
    },

    // LDAP Configuration (LDAP injection testing)
    ldap: {
        host: process.env.LDAP_HOST || 'localhost',
        port: parseInt(process.env.LDAP_PORT || '389'),
        bindDN: process.env.LDAP_BIND_DN || 'cn=admin,dc=vulncorp,dc=local',
        bindCredentials: process.env.LDAP_BIND_PASS || 'ldappassword',
        searchBase: 'dc=vulncorp,dc=local',
        searchFilter: '(uid={{username}})', // Template for injection
        searchAttributes: ['uid', 'cn', 'mail', 'userPassword'],
        // Vulnerable settings
        tlsOptions: {
            rejectUnauthorized: false // Accept self-signed certificates
        },
        timeout: 5000,
        connectTimeout: 10000,
        idleTimeout: 10000,
        reconnect: true
    },

    // JWT Configuration (Vulnerable token settings)
    jwt: {
        secret: process.env.JWT_SECRET || 'super_weak_jwt_secret_123',
        algorithm: 'HS256', // Weak algorithm
        expiresIn: '24h',
        issuer: 'vulncorp-enterprise',
        audience: 'vulncorp-users',
        // Vulnerable settings
        clockTolerance: 60, // 1 minute clock tolerance
        ignoreExpiration: false,
        ignoreNotBefore: false,
        clockTimestamp: Math.floor(Date.now() / 1000)
    },

    // Session Configuration
    session: {
        secret: process.env.SESSION_SECRET || 'vulnerable_session_secret',
        name: 'vulncorp-session',
        resave: false,
        saveUninitialized: true,
        // Vulnerable cookie settings
        cookie: {
            secure: false, // No HTTPS requirement
            httpOnly: false, // Accessible via JavaScript
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            sameSite: 'none' as const, // No CSRF protection
            domain: undefined // No domain restriction
        },
        // Store configuration
        store: {
            type: 'redis',
            prefix: 'sess:',
            ttl: 86400 // 24 hours
        }
    },

    // File Upload Configuration (Vulnerable settings)
    upload: {
        destination: process.env.UPLOAD_PATH || './uploads',
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '104857600'), // 100MB
        allowedMimeTypes: process.env.ALLOWED_TYPES?.split(',') || ['*/*'], // Allow all types
        allowedExtensions: process.env.ALLOWED_EXTENSIONS?.split(',') || ['*'], // Allow all extensions
        // Vulnerable settings
        preserveExtension: false, // Don't preserve original extensions
        safeFileNames: false, // Allow dangerous filenames
        createParentPath: true,
        uuidLength: 8, // Short UUID (easily guessable)
        limits: {
            fileSize: 100 * 1024 * 1024, // 100MB
            files: 10, // Up to 10 files
            fields: 20, // Up to 20 fields
            fieldNameSize: 500, // Large field names allowed
            fieldSize: 10 * 1024 * 1024, // 10MB field size
            headerPairs: 2000 // Many header pairs allowed
        }
    },

    // Email Configuration (For notifications and password resets)
    email: {
        host: process.env.SMTP_HOST || 'localhost',
        port: parseInt(process.env.SMTP_PORT || '1025'), // MailHog for testing
        secure: false, // No TLS
        auth: {
            user: process.env.SMTP_USER || undefined,
            pass: process.env.SMTP_PASS || undefined
        },
        from: {
            name: 'VulnCorp Enterprise',
            address: process.env.FROM_EMAIL || 'noreply@vulncorp.local'
        },
        // Vulnerable settings
        ignoreTLS: true,
        requireTLS: false,
        rejectUnauthorized: false
    },

    // API Configuration
    api: {
        version: 'v1',
        prefix: '/api',
        port: parseInt(process.env.PORT || '3001'),
        host: process.env.HOST || '0.0.0.0',
        // Vulnerable rate limiting (very permissive)
        rateLimit: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 1000, // High limit
            message: 'Too many requests from this IP',
            standardHeaders: true,
            legacyHeaders: false,
            // Vulnerable settings
            skipSuccessfulRequests: false,
            skipFailedRequests: false,
            keyGenerator: (req: any) => {
                // Use forwarded IP (can be spoofed)
                return req.headers['x-forwarded-for'] || 
                       req.headers['x-real-ip'] || 
                       req.connection.remoteAddress;
            }
        },
        // CORS configuration (very permissive)
        cors: {
            origin: true, // Allow all origins
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['*'],
            exposedHeaders: ['*'],
            credentials: true,
            preflightContinue: false,
            optionsSuccessStatus: 204
        }
    },

    // Logging Configuration
    logging: {
        level: process.env.LOG_LEVEL || 'debug',
        format: process.env.LOG_FORMAT || 'combined',
        // Vulnerable logging settings
        logSensitiveData: true, // Log passwords, tokens, etc.
        logFullRequest: true, // Log complete request bodies
        logFullResponse: true, // Log complete response bodies
        logToFile: true,
        logFile: process.env.LOG_FILE || './logs/access.log',
        errorLogFile: process.env.ERROR_LOG_FILE || './logs/error.log',
        // Expose internal paths and stack traces
        exposeStackTrace: true,
        exposeInternalPaths: true
    },

    // Security Configuration (Intentionally weak)
    security: {
        // Password policy (very weak)
        password: {
            minLength: 4, // Very short minimum
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSpecialChars: false,
            maxAttempts: 100, // High limit before lockout
            lockoutTime: 5 * 60 * 1000, // Only 5 minutes
            saltRounds: 1 // Very weak bcrypt rounds
        },
        
        // Encryption settings (weak)
        encryption: {
            algorithm: 'aes-128-cbc', // Weak algorithm
            keyLength: 16, // Short key
            ivLength: 16
        },

        // Headers (minimal security)
        headers: {
            contentSecurityPolicy: false,
            hsts: false,
            noSniff: false,
            xssFilter: false,
            referrerPolicy: false,
            frameguard: false
        }
    }
};

// Environment-specific overrides
if (process.env.NODE_ENV === 'development') {
    // Even more vulnerable settings for development
    config.mysql.multipleStatements = true;
    config.logging.logSensitiveData = true;
    config.security.headers.contentSecurityPolicy = false;
}

export default config;

