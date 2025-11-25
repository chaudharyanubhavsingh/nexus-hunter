/**
 * SQL Injection Vulnerability Routes
 * 
 * Comprehensive SQL injection testing endpoints
 * Contains all major SQL injection vulnerability types
 */

import express from 'express';
import mysql from 'mysql2/promise';
import { config } from '@config/database';
import { logger, securityLogger } from '@utils/logger';

const router = express.Router();

// Create MySQL connection pool
const pool = mysql.createPool(config.mysql);

// Helper function to execute vulnerable queries
async function executeVulnerableQuery(query: string, params: any[] = []) {
    const startTime = Date.now();
    try {
        const [rows] = await pool.execute(query, params);
        const executionTime = Date.now() - startTime;
        
        // Log the query (vulnerability: exposes SQL structure)
        securityLogger.logQuery(query, params, rows, executionTime);
        
        return { success: true, data: rows, executionTime };
    } catch (error: any) {
        const executionTime = Date.now() - startTime;
        
        // Log errors with sensitive information
        securityLogger.logError(error, { query, params, executionTime });
        
        return { 
            success: false, 
            error: error.message, 
            sqlState: error.sqlState,
            errno: error.errno,
            code: error.code,
            query, // VULNERABLE: Expose query in error
            executionTime 
        };
    }
}

/**
 * BASIC SQL INJECTION VULNERABILITIES
 */

// 1. Classic Login Bypass (Union-based)
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: Direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    const result = await executeVulnerableQuery(query);
    
    if (result.success && Array.isArray(result.data) && result.data.length > 0) {
        res.json({
            success: true,
            message: 'Login successful',
            user: result.data[0], // VULNERABLE: Expose all user data
            query: query // VULNERABLE: Expose SQL query
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Login failed',
            error: result.error,
            query: query, // VULNERABLE: Expose query even on failure
            hint: "Try: admin' OR '1'='1' --"
        });
    }
});

// 2. Search with Error-based SQL Injection
router.get('/search', async (req, res) => {
    const { q: searchTerm } = req.query;
    
    if (!searchTerm) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    // VULNERABLE: Direct concatenation in LIKE clause
    const query = `SELECT id, name, description, price FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;
    
    const result = await executeVulnerableQuery(query);
    
    res.json({
        searchTerm,
        query, // VULNERABLE: Expose query
        results: result.success ? result.data : [],
        error: result.error,
        executionTime: result.executionTime,
        hint: result.error ? "Try: test' UNION SELECT 1,version(),user(),4 --" : undefined
    });
});

// 3. User Profile with Blind SQL Injection
router.get('/profile/:id', async (req, res) => {
    const { id } = req.params;
    
    // VULNERABLE: Direct parameter insertion
    const query = `SELECT username, email, role FROM users WHERE id = ${id}`;
    
    const result = await executeVulnerableQuery(query);
    
    if (result.success && Array.isArray(result.data) && result.data.length > 0) {
        res.json({
            profile: result.data[0],
            query: query,
            hint: "Try: 1 OR SLEEP(5)"
        });
    } else {
        res.status(404).json({
            error: 'User not found',
            sqlError: result.error,
            query: query,
            hint: "Try: 1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a"
        });
    }
});

/**
 * ADVANCED SQL INJECTION VULNERABILITIES
 */

// 4. ORDER BY Injection
router.get('/users', async (req, res) => {
    const { sort = 'id', order = 'ASC' } = req.query;
    
    // VULNERABLE: Direct parameter in ORDER BY
    const query = `SELECT id, username, email, role FROM users ORDER BY ${sort} ${order}`;
    
    const result = await executeVulnerableQuery(query);
    
    res.json({
        users: result.success ? result.data : [],
        sorting: { sort, order },
        query: query,
        error: result.error,
        hint: "Try: sort=(SELECT CASE WHEN (1=1) THEN id ELSE username END)"
    });
});

// 5. LIMIT/OFFSET Injection
router.get('/products', async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    
    // VULNERABLE: Direct parameter in LIMIT/OFFSET
    const query = `SELECT * FROM products LIMIT ${limit} OFFSET ${offset}`;
    
    const result = await executeVulnerableQuery(query);
    
    res.json({
        products: result.success ? result.data : [],
        pagination: { page: Number(page), limit: Number(limit), offset },
        query: query,
        error: result.error,
        hint: "Try: limit=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
    });
});

// 6. Time-based Blind SQL Injection
router.post('/reset-password', async (req, res) => {
    const { email } = req.body;
    
    // VULNERABLE: Time-based blind injection
    const query = `SELECT id FROM users WHERE email = '${email}'`;
    
    const startTime = Date.now();
    const result = await executeVulnerableQuery(query);
    const responseTime = Date.now() - startTime;
    
    res.json({
        message: 'Password reset instructions sent if email exists',
        email: email,
        query: query,
        responseTime: responseTime,
        hint: "Try: test@test.com' OR SLEEP(5) --"
    });
});

// 7. Second-order SQL Injection
router.post('/update-profile', async (req, res) => {
    const { userId, bio } = req.body;
    
    // First query: Store user input (seemingly safe)
    const insertQuery = `UPDATE users SET bio = ? WHERE id = ?`;
    const insertResult = await executeVulnerableQuery(insertQuery, [bio, userId]);
    
    if (insertResult.success) {
        // Second query: VULNERABLE - uses stored data without sanitization
        const selectQuery = `SELECT username, bio FROM users WHERE bio LIKE '%${bio}%'`;
        const selectResult = await executeVulnerableQuery(selectQuery);
        
        res.json({
            message: 'Profile updated successfully',
            updatedUsers: selectResult.data,
            queries: [insertQuery, selectQuery],
            hint: "Try bio: test' UNION SELECT version(), user() --"
        });
    } else {
        res.status(500).json({
            error: 'Failed to update profile',
            details: insertResult.error
        });
    }
});

// 8. JSON-based SQL Injection
router.post('/search-advanced', async (req, res) => {
    const { filters } = req.body;
    
    if (!filters || typeof filters !== 'object') {
        return res.status(400).json({ error: 'Filters object is required' });
    }
    
    let whereClause = '1=1';
    const conditions = [];
    
    // VULNERABLE: Build WHERE clause from JSON without proper escaping
    for (const [field, value] of Object.entries(filters)) {
        if (typeof value === 'string') {
            conditions.push(`${field} LIKE '%${value}%'`);
        } else if (typeof value === 'number') {
            conditions.push(`${field} = ${value}`);
        } else if (Array.isArray(value)) {
            const values = value.map(v => `'${v}'`).join(',');
            conditions.push(`${field} IN (${values})`);
        }
    }
    
    if (conditions.length > 0) {
        whereClause += ' AND (' + conditions.join(' OR ') + ')';
    }
    
    const query = `SELECT * FROM products WHERE ${whereClause}`;
    const result = await executeVulnerableQuery(query);
    
    res.json({
        filters,
        whereClause,
        query,
        results: result.success ? result.data : [],
        error: result.error,
        hint: 'Try filters: {"name": "test\\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 --"}'
    });
});

/**
 * STORED PROCEDURE INJECTION
 */
router.post('/admin/create-user', async (req, res) => {
    const { username, email, role } = req.body;
    
    // VULNERABLE: Stored procedure call with direct parameter insertion
    const query = `CALL CreateUser('${username}', '${email}', '${role}')`;
    
    const result = await executeVulnerableQuery(query);
    
    res.json({
        message: 'User creation attempted',
        parameters: { username, email, role },
        query,
        result: result.success ? result.data : null,
        error: result.error,
        hint: "Try username: admin'); DROP TABLE users; --"
    });
});

/**
 * INFORMATION DISCLOSURE ENDPOINTS
 */

// Database schema information
router.get('/schema', async (req, res) => {
    const queries = [
        'SELECT schema_name FROM information_schema.schemata',
        'SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()',
        'SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = DATABASE()',
        'SELECT version(), user(), database()',
        'SHOW VARIABLES',
        'SHOW STATUS'
    ];
    
    const results = {};
    for (const [index, query] of queries.entries()) {
        const result = await executeVulnerableQuery(query);
        results[`query_${index + 1}`] = {
            query,
            data: result.data,
            error: result.error
        };
    }
    
    res.json({
        message: 'Database schema information',
        results,
        warning: 'This endpoint exposes sensitive database information'
    });
});

// Raw query execution (extremely dangerous)
router.post('/admin/execute', async (req, res) => {
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ error: 'SQL query is required' });
    }
    
    // VULNERABLE: Execute any SQL query directly
    const result = await executeVulnerableQuery(query);
    
    res.json({
        message: 'Query executed',
        query,
        result: result.data,
        error: result.error,
        executionTime: result.executionTime,
        warning: 'This endpoint allows arbitrary SQL execution'
    });
});

// Export router and testing information
export default router;

// Export vulnerability information for documentation
export const sqlInjectionVulnerabilities = {
    endpoints: [
        {
            path: '/login',
            method: 'POST',
            vulnerability: 'Classic Authentication Bypass',
            payloads: ["admin' OR '1'='1' --", "' UNION SELECT 1,2,3,4 --"]
        },
        {
            path: '/search',
            method: 'GET',
            vulnerability: 'Error-based SQL Injection',
            payloads: ["test' UNION SELECT 1,version(),user(),4 --"]
        },
        {
            path: '/profile/:id',
            method: 'GET',
            vulnerability: 'Blind SQL Injection',
            payloads: ["1 OR SLEEP(5)", "1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a"]
        },
        {
            path: '/users',
            method: 'GET',
            vulnerability: 'ORDER BY Injection',
            payloads: ["(SELECT CASE WHEN (1=1) THEN id ELSE username END)"]
        },
        {
            path: '/products',
            method: 'GET',
            vulnerability: 'LIMIT/OFFSET Injection',
            payloads: ["1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"]
        },
        {
            path: '/reset-password',
            method: 'POST',
            vulnerability: 'Time-based Blind Injection',
            payloads: ["test@test.com' OR SLEEP(5) --"]
        },
        {
            path: '/update-profile',
            method: 'POST',
            vulnerability: 'Second-order SQL Injection',
            payloads: ["test' UNION SELECT version(), user() --"]
        },
        {
            path: '/search-advanced',
            method: 'POST',
            vulnerability: 'JSON-based SQL Injection',
            payloads: ['{"name": "test\\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 --"}']
        },
        {
            path: '/admin/create-user',
            method: 'POST',
            vulnerability: 'Stored Procedure Injection',
            payloads: ["admin'); DROP TABLE users; --"]
        },
        {
            path: '/admin/execute',
            method: 'POST',
            vulnerability: 'Direct Query Execution',
            payloads: ["SELECT * FROM users", "DROP TABLE products"]
        }
    ],
    totalVulnerabilities: 10,
    riskLevel: 'CRITICAL',
    description: 'Comprehensive SQL injection testing suite covering all major injection types'
};

