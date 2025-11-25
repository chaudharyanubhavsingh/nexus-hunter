/**
 * Cross-Site Scripting (XSS) Vulnerability Routes
 * 
 * Comprehensive XSS testing endpoints covering all major XSS types
 * Contains reflected, stored, DOM-based, and advanced XSS vulnerabilities
 */

import express from 'express';
import mysql from 'mysql2/promise';
import { config } from '@config/database';
import { logger, securityLogger } from '@utils/logger';

const router = express.Router();
const pool = mysql.createPool(config.mysql);

/**
 * REFLECTED XSS VULNERABILITIES
 */

// 1. Basic Reflected XSS in Search
router.get('/search', (req, res) => {
    const { q: searchTerm } = req.query;
    
    if (!searchTerm) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    // VULNERABLE: Direct reflection without encoding
    const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnCorp Search Results</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>VulnCorp Enterprise Search</h1>
        <div class="search-info">
            <p>You searched for: <strong>${searchTerm}</strong></p>
            <p>Search results for "${searchTerm}" will appear below:</p>
        </div>
        <div class="results">
            <p>No results found for query: ${searchTerm}</p>
        </div>
        <script>
            // VULNERABLE: Reflected in JavaScript context
            console.log('Search performed for: ${searchTerm}');
            document.title = 'Search: ${searchTerm}';
        </script>
    </body>
    </html>`;
    
    res.send(htmlResponse);
});

// 2. Reflected XSS in Error Messages
router.get('/error', (req, res) => {
    const { message, code } = req.query;
    
    // VULNERABLE: Error message reflection
    res.status(400).json({
        success: false,
        error: `An error occurred: ${message}`, // Direct reflection
        errorCode: code,
        timestamp: new Date().toISOString(),
        details: {
            userMessage: message,
            errorType: 'UserError',
            suggestion: `Please check your input: ${message}`
        },
        hint: 'Try: ?message=<script>alert("Reflected XSS")</script>'
    });
});

// 3. Reflected XSS in HTTP Headers
router.get('/header-reflection', (req, res) => {
    const userAgent = req.get('User-Agent') || 'Unknown';
    const referer = req.get('Referer') || 'Direct';
    const customHeader = req.get('X-Custom-Header') || 'None';
    
    // VULNERABLE: Reflect headers in response
    res.json({
        message: 'Header reflection test',
        userAgent: `Your browser: ${userAgent}`, // Reflected header
        referrer: `You came from: ${referer}`, // Reflected header
        customHeader: `Custom header value: ${customHeader}`, // Reflected header
        htmlContent: `<div>User-Agent: ${userAgent}</div>`, // HTML context
        hint: 'Try setting X-Custom-Header: <img src=x onerror=alert("XSS")>'
    });
});

/**
 * STORED XSS VULNERABILITIES
 */

// 4. Stored XSS in Comments
router.post('/comments', async (req, res) => {
    const { productId, comment, author } = req.body;
    
    if (!productId || !comment || !author) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    try {
        // VULNERABLE: Store comment without sanitization
        const insertQuery = 'INSERT INTO product_comments (product_id, author, comment, created_at) VALUES (?, ?, ?, NOW())';
        await pool.execute(insertQuery, [productId, author, comment]);
        
        securityLogger.logAPI(req, res, 0);
        
        res.json({
            success: true,
            message: 'Comment saved successfully',
            data: { productId, author, comment },
            hint: 'Try comment: <script>alert("Stored XSS")</script>'
        });
    } catch (error: any) {
        res.status(500).json({
            error: 'Failed to save comment',
            details: error.message
        });
    }
});

// 5. Get Comments (Displays Stored XSS)
router.get('/comments/:productId', async (req, res) => {
    const { productId } = req.params;
    
    try {
        const [rows] = await pool.execute(
            'SELECT author, comment, created_at FROM product_comments WHERE product_id = ? ORDER BY created_at DESC',
            [productId]
        );
        
        // VULNERABLE: Return comments without encoding
        const htmlComments = (rows as any[]).map(row => `
            <div class="comment">
                <strong>${row.author}</strong> said:
                <p>${row.comment}</p>
                <small>Posted: ${row.created_at}</small>
            </div>
        `).join('');
        
        const htmlResponse = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Product Comments</title>
        </head>
        <body>
            <h1>Comments for Product ${productId}</h1>
            <div class="comments">
                ${htmlComments}
            </div>
            <script>
                // VULNERABLE: Comments included in JavaScript
                const comments = ${JSON.stringify(rows)};
                console.log('Loaded comments:', comments);
            </script>
        </body>
        </html>`;
        
        res.send(htmlResponse);
    } catch (error: any) {
        res.status(500).json({
            error: 'Failed to retrieve comments',
            details: error.message
        });
    }
});

// 6. Stored XSS in User Profiles
router.post('/profile', async (req, res) => {
    const { userId, bio, website, interests } = req.body;
    
    try {
        // VULNERABLE: Store profile data without sanitization
        await pool.execute(
            'UPDATE users SET bio = ?, website = ?, interests = ? WHERE id = ?',
            [bio, website, interests, userId]
        );
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: { userId, bio, website, interests },
            hint: 'Try bio: <img src=x onerror=alert("Stored XSS in profile")>'
        });
    } catch (error: any) {
        res.status(500).json({
            error: 'Failed to update profile',
            details: error.message
        });
    }
});

/**
 * DOM-BASED XSS VULNERABILITIES
 */

// 7. DOM XSS via Fragment/Hash
router.get('/dom-xss', (req, res) => {
    const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>DOM XSS Test</title>
    </head>
    <body>
        <h1>DOM-based XSS Vulnerability</h1>
        <div id="content">
            <p>Loading content...</p>
        </div>
        
        <script>
            // VULNERABLE: Direct DOM manipulation with user input
            function loadContent() {
                const hash = window.location.hash.substring(1);
                if (hash) {
                    document.getElementById('content').innerHTML = '<p>Content: ' + hash + '</p>';
                }
            }
            
            // VULNERABLE: Using innerHTML with user-controlled data
            function updateFromURL() {
                const urlParams = new URLSearchParams(window.location.search);
                const message = urlParams.get('message');
                if (message) {
                    document.getElementById('content').innerHTML = '<div>Message: ' + message + '</div>';
                }
            }
            
            // Load content on page load
            window.onload = function() {
                loadContent();
                updateFromURL();
            };
            
            // Listen for hash changes
            window.onhashchange = loadContent;
        </script>
        
        <div>
            <h3>Test URLs:</h3>
            <ul>
                <li><a href="#<img src=x onerror=alert('DOM XSS via hash')>">Hash-based XSS</a></li>
                <li><a href="?message=<script>alert('DOM XSS via query')</script>">Query-based XSS</a></li>
            </ul>
        </div>
    </body>
    </html>`;
    
    res.send(htmlResponse);
});

/**
 * ADVANCED XSS VULNERABILITIES
 */

// 8. XSS in JSON Responses
router.get('/user-data/:id', async (req, res) => {
    const { id } = req.params;
    const { callback } = req.query; // JSONP callback
    
    try {
        const [rows] = await pool.execute(
            'SELECT username, email, bio, website FROM users WHERE id = ?',
            [id]
        );
        
        const userData = rows[0] || { error: 'User not found' };
        
        if (callback) {
            // VULNERABLE: JSONP without callback validation
            const jsonpResponse = `${callback}(${JSON.stringify(userData)});`;
            res.setHeader('Content-Type', 'application/javascript');
            res.send(jsonpResponse);
        } else {
            // VULNERABLE: User data may contain XSS payloads
            res.json({
                user: userData,
                hint: 'Try: ?callback=alert("JSONP XSS")//'
            });
        }
    } catch (error: any) {
        res.status(500).json({
            error: 'Failed to retrieve user data',
            details: error.message
        });
    }
});

// 9. XSS via File Upload (SVG)
router.post('/upload-avatar', (req, res) => {
    if (!req.files || !req.files.avatar) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const avatar = req.files.avatar as any;
    const fileName = avatar.name;
    const uploadPath = `./uploads/avatars/${fileName}`;
    
    // VULNERABLE: No file type validation, allows SVG with XSS
    avatar.mv(uploadPath, (err: any) => {
        if (err) {
            return res.status(500).json({
                error: 'File upload failed',
                details: err.message
            });
        }
        
        // VULNERABLE: Return file path that can be accessed directly
        res.json({
            success: true,
            message: 'Avatar uploaded successfully',
            fileName: fileName,
            filePath: `/uploads/avatars/${fileName}`,
            fileUrl: `http://localhost:3001/uploads/avatars/${fileName}`,
            hint: 'Try uploading an SVG file with: <script>alert("XSS via SVG")</script>'
        });
    });
});

// 10. XSS via Template Injection
router.post('/generate-report', (req, res) => {
    const { title, content, template } = req.body;
    
    // VULNERABLE: Template string without proper escaping
    let reportTemplate = template || `
        <html>
        <head><title>{{title}}</title></head>
        <body>
            <h1>{{title}}</h1>
            <div>{{content}}</div>
            <footer>Generated at: {{timestamp}}</footer>
        </body>
        </html>
    `;
    
    // VULNERABLE: Simple template replacement without escaping
    const generatedReport = reportTemplate
        .replace(/{{title}}/g, title || 'Untitled Report')
        .replace(/{{content}}/g, content || 'No content provided')
        .replace(/{{timestamp}}/g, new Date().toISOString());
    
    res.send(generatedReport);
});

/**
 * CSP BYPASS VULNERABILITIES
 */

// 11. XSS with Content Security Policy Bypass
router.get('/csp-bypass', (req, res) => {
    const { payload } = req.query;
    
    // VULNERABLE: Weak CSP with unsafe-inline
    res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data: blob:;");
    
    const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSP Bypass Test</title>
    </head>
    <body>
        <h1>CSP Bypass Vulnerability</h1>
        <div id="payload-display">
            Payload: ${payload || 'None'}
        </div>
        
        <!-- VULNERABLE: Inline script with user input -->
        <script>
            const userPayload = '${payload || ''}';
            document.getElementById('payload-display').innerHTML += '<br>Executed: ' + userPayload;
        </script>
        
        <!-- VULNERABLE: Data URL injection -->
        <iframe src="data:text/html,${encodeURIComponent(payload || '')}" width="300" height="200"></iframe>
        
        <div>
            <h3>Test Payloads:</h3>
            <ul>
                <li><code>?payload=&lt;img src=x onerror=alert('CSP bypass')&gt;</code></li>
                <li><code>?payload=&lt;script&gt;alert('Inline script bypass')&lt;/script&gt;</code></li>
            </ul>
        </div>
    </body>
    </html>`;
    
    res.send(htmlResponse);
});

/**
 * XSS TESTING PLAYGROUND
 */

// 12. Interactive XSS Testing Environment
router.get('/playground', (req, res) => {
    const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Testing Playground</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .test-section { border: 1px solid #ccc; padding: 15px; margin: 10px 0; }
            .vulnerable { background-color: #ffebee; }
            .input-field { width: 100%; padding: 8px; margin: 5px 0; }
            .output { border: 1px solid #ddd; padding: 10px; background: #f9f9f9; }
            pre { background: #f0f0f0; padding: 10px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🎯 XSS Vulnerability Testing Playground</h1>
        <p><strong>Warning:</strong> This environment contains intentional XSS vulnerabilities for security testing.</p>
        
        <div class="test-section vulnerable">
            <h3>1. Reflected XSS Test</h3>
            <form id="xssForm" onsubmit="return false;">
                <input type="text" id="xssInput" class="input-field" placeholder="Enter your payload here...">
                <button onclick="testReflectedXSS()">Test Reflected XSS</button>
            </form>
            <div id="xssOutput" class="output"></div>
        </div>
        
        <div class="test-section vulnerable">
            <h3>2. DOM XSS Test</h3>
            <input type="text" id="domInput" class="input-field" placeholder="DOM payload...">
            <button onclick="testDOMXSS()">Test DOM XSS</button>
            <div id="domOutput" class="output"></div>
        </div>
        
        <div class="test-section">
            <h3>3. Common XSS Payloads</h3>
            <pre>
Basic:           &lt;script&gt;alert('XSS')&lt;/script&gt;
Image:           &lt;img src=x onerror=alert('XSS')&gt;
SVG:             &lt;svg onload=alert('XSS')&gt;
Input:           &lt;input autofocus onfocus=alert('XSS')&gt;
Body:            &lt;body onload=alert('XSS')&gt;
JavaScript URL:  javascript:alert('XSS')
Data URL:        data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;
            </pre>
        </div>
        
        <script>
            function testReflectedXSS() {
                const input = document.getElementById('xssInput').value;
                const output = document.getElementById('xssOutput');
                // VULNERABLE: Direct innerHTML assignment
                output.innerHTML = 'Your input: ' + input;
            }
            
            function testDOMXSS() {
                const input = document.getElementById('domInput').value;
                const output = document.getElementById('domOutput');
                // VULNERABLE: eval() with user input
                try {
                    eval('output.innerHTML = "Result: " + "' + input + '"');
                } catch (e) {
                    output.innerHTML = 'Error: ' + e.message;
                }
            }
        </script>
    </body>
    </html>`;
    
    res.send(htmlResponse);
});

export default router;

// Export vulnerability information for documentation
export const xssVulnerabilities = {
    endpoints: [
        {
            path: '/search',
            method: 'GET',
            vulnerability: 'Reflected XSS in Search',
            payloads: ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
        },
        {
            path: '/error',
            method: 'GET',
            vulnerability: 'Reflected XSS in Error Messages',
            payloads: ['<script>alert("Error XSS")</script>']
        },
        {
            path: '/header-reflection',
            method: 'GET',
            vulnerability: 'XSS via HTTP Headers',
            headers: { 'X-Custom-Header': '<img src=x onerror=alert("Header XSS")>' }
        },
        {
            path: '/comments',
            method: 'POST',
            vulnerability: 'Stored XSS in Comments',
            payloads: ['<script>alert("Stored XSS")</script>']
        },
        {
            path: '/comments/:productId',
            method: 'GET',
            vulnerability: 'Stored XSS Display',
            description: 'Displays stored XSS payloads from comments'
        },
        {
            path: '/profile',
            method: 'POST',
            vulnerability: 'Stored XSS in User Profiles',
            payloads: ['<img src=x onerror=alert("Profile XSS")>']
        },
        {
            path: '/dom-xss',
            method: 'GET',
            vulnerability: 'DOM-based XSS',
            payloads: ['#<img src=x onerror=alert("DOM XSS")>']
        },
        {
            path: '/user-data/:id',
            method: 'GET',
            vulnerability: 'JSONP XSS',
            payloads: ['?callback=alert("JSONP XSS")//']
        },
        {
            path: '/upload-avatar',
            method: 'POST',
            vulnerability: 'XSS via File Upload (SVG)',
            description: 'Upload SVG file with XSS payload'
        },
        {
            path: '/generate-report',
            method: 'POST',
            vulnerability: 'XSS via Template Injection',
            payloads: ['<script>alert("Template XSS")</script>']
        },
        {
            path: '/csp-bypass',
            method: 'GET',
            vulnerability: 'CSP Bypass XSS',
            payloads: ['<img src=x onerror=alert("CSP bypass")>']
        },
        {
            path: '/playground',
            method: 'GET',
            vulnerability: 'Interactive XSS Testing Environment',
            description: 'Comprehensive XSS testing playground'
        }
    ],
    totalVulnerabilities: 12,
    riskLevel: 'HIGH',
    description: 'Comprehensive XSS testing suite covering reflected, stored, DOM-based, and advanced XSS techniques'
};

