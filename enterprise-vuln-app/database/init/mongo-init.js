// VulnCorp Enterprise MongoDB Initialization
// Vulnerable NoSQL database setup for security testing
// DO NOT USE IN PRODUCTION

// Switch to our database
use('vulncorp_nosql');

// Create collections with vulnerable data structures

// Users collection with NoSQL injection vulnerabilities
db.createCollection('users');
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 });

// Products collection for NoSQL injection testing
db.createCollection('products');
db.products.createIndex({ "sku": 1 }, { unique: true });
db.products.createIndex({ "name": "text", "description": "text" });

// Session storage (vulnerable)
db.createCollection('sessions');
db.sessions.createIndex({ "expires": 1 }, { expireAfterSeconds: 0 });

// Logs collection for injection testing
db.createCollection('logs');
db.logs.createIndex({ "timestamp": -1 });
db.logs.createIndex({ "level": 1, "timestamp": -1 });

// Analytics collection
db.createCollection('analytics');
db.analytics.createIndex({ "date": -1, "type": 1 });

// Comments/Reviews (vulnerable to injection)
db.createCollection('reviews');
db.reviews.createIndex({ "productId": 1, "rating": -1 });

// Initialize with vulnerable sample data
db.users.insertMany([
    {
        _id: ObjectId("60f1234567890abcdef12345"),
        username: "admin",
        password: "21232f297a57a5a743894a0e4a801fc3", // MD5 of 'admin'
        email: "admin@vulncorp.local",
        role: "admin",
        profile: {
            firstName: "Admin",
            lastName: "User",
            bio: "<script>alert('XSS')</script>", // XSS vulnerability
            preferences: {
                notifications: true,
                theme: "dark"
            }
        },
        apiKey: "admin_api_key_12345",
        permissions: ["read", "write", "admin"],
        metadata: {
            lastLogin: new Date(),
            loginCount: 42,
            settings: "function() { return process.env; }" // Code injection risk
        }
    },
    {
        _id: ObjectId("60f1234567890abcdef12346"),
        username: "testuser",
        password: "5d41402abc4b2a76b9719d911017c592", // MD5 of 'hello'
        email: "test@vulncorp.local",
        role: "user",
        profile: {
            firstName: "Test",
            lastName: "User",
            bio: "Regular test user account"
        },
        apiKey: "test_api_key_67890"
    }
]);

db.products.insertMany([
    {
        _id: ObjectId("60f1234567890abcdef54321"),
        sku: "VULN-001",
        name: "Enterprise Security Scanner",
        description: "Professional security scanning tool",
        price: 999.99,
        category: "software",
        inventory: 100,
        tags: ["security", "scanning", "enterprise"],
        metadata: {
            supplier: "VulnCorp",
            cost: 500.00, // Sensitive business data
            margin: 49.95,
            notes: "eval('return this')" // Code injection vulnerability
        },
        reviews: [],
        searchable: {
            keywords: ["security", "scanner", "tool"],
            filters: {
                price: { $gte: 500, $lte: 2000 },
                category: { $in: ["software", "security"] }
            }
        }
    }
]);

// Vulnerable session data
db.sessions.insertOne({
    _id: "sess:admin:12345",
    sessionId: "admin_session_12345",
    userId: ObjectId("60f1234567890abcdef12345"),
    data: {
        user: {
            id: ObjectId("60f1234567890abcdef12345"),
            username: "admin",
            role: "admin",
            serializedObject: "O:4:\"User\":3:{s:2:\"id\";s:1:\"1\";s:8:\"username\";s:5:\"admin\";s:4:\"role\";s:5:\"admin\";}" // Deserialization vulnerability
        },
        permissions: ["*"],
        csrf_token: "weak_csrf_token"
    },
    expires: new Date(Date.now() + 86400000),
    ipAddress: "127.0.0.1",
    userAgent: "Mozilla/5.0..."
});

// Vulnerable log entries
db.logs.insertMany([
    {
        timestamp: new Date(),
        level: "info",
        message: "User login successful",
        context: {
            userId: ObjectId("60f1234567890abcdef12345"),
            username: "admin",
            password: "admin", // Password logged (vulnerability)
            ipAddress: "192.168.1.100",
            sessionData: "serialized_session_data_here"
        },
        query: {
            // Raw query object (injection risk)
            $where: "function() { return this.username == 'admin' && this.password == 'admin' }"
        }
    },
    {
        timestamp: new Date(),
        level: "error",
        message: "Database error occurred",
        context: {
            error: "MongoError: E11000 duplicate key error",
            query: "{ username: { $regex: '.*' + userInput + '.*' } }", // Regex injection
            stackTrace: "Full stack trace with sensitive paths..."
        }
    }
]);

// Analytics data for aggregation vulnerabilities
db.analytics.insertMany([
    {
        date: new Date(),
        type: "pageview",
        url: "/admin/users",
        userId: ObjectId("60f1234567890abcdef12345"),
        metadata: {
            referrer: "javascript:alert('XSS')", // XSS in analytics
            userAgent: "Mozilla/5.0...",
            customData: "eval(process.mainModule.require('child_process').exec('whoami'))" // RCE risk
        }
    }
]);

// Reviews with injection vulnerabilities
db.reviews.insertMany([
    {
        productId: ObjectId("60f1234567890abcdef54321"),
        userId: ObjectId("60f1234567890abcdef12346"),
        rating: 5,
        title: "Great product!",
        content: "<script>alert('Stored XSS in review')</script>", // Stored XSS
        metadata: {
            ipAddress: "192.168.1.50",
            device: "desktop",
            customFields: {
                // Template injection vulnerability
                template: "{{constructor.constructor('return process.env')()}}"
            }
        },
        timestamp: new Date()
    }
]);

// Create vulnerable indexes for testing
db.users.createIndex({ 
    "profile.bio": "text",
    "metadata.settings": "text" 
});

// Create a view with vulnerable aggregation pipeline
db.createView(
    "userStats",
    "users",
    [
        {
            $project: {
                username: 1,
                email: 1,
                role: 1,
                // Vulnerable aggregation allowing code execution
                stats: {
                    $function: {
                        body: "function() { return eval(this.metadata.settings) }",
                        args: [],
                        lang: "js"
                    }
                }
            }
        }
    ]
);

print("MongoDB vulnerable database initialized successfully!");
print("Collections created:");
print("- users (with XSS and code injection vulnerabilities)");
print("- products (with NoSQL injection points)");
print("- sessions (vulnerable session storage)");
print("- logs (information disclosure vulnerabilities)");
print("- analytics (aggregation pipeline vulnerabilities)");
print("- reviews (stored XSS vulnerabilities)");
print("");
print("WARNING: This database contains intentional vulnerabilities!");
print("Only use in controlled testing environments.");

