-- VulnCorp Enterprise Database Schema
-- Comprehensive vulnerable database design for security testing
-- DO NOT USE IN PRODUCTION - Contains intentional vulnerabilities

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- Create database with vulnerable charset
CREATE DATABASE IF NOT EXISTS vulncorp_enterprise 
CHARACTER SET utf8 COLLATE utf8_general_ci;

USE vulncorp_enterprise;

-- ===================================
-- USER MANAGEMENT & AUTHENTICATION
-- ===================================

-- Users table with multiple vulnerabilities
CREATE TABLE users (
    id INT(11) NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL, -- MD5 hashed (vulnerable)
    password_hint VARCHAR(255), -- Password hints exposed
    role ENUM('admin','manager','employee','customer') DEFAULT 'customer',
    department_id INT(11),
    salary DECIMAL(10,2), -- Sensitive data exposure
    ssn VARCHAR(11), -- PII exposure
    api_key VARCHAR(100), -- Exposed API keys
    reset_token VARCHAR(100), -- Predictable reset tokens
    reset_expires DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    last_login DATETIME,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Vulnerable stored XSS
    bio TEXT, -- No sanitization
    profile_image VARCHAR(255),
    PRIMARY KEY (id),
    UNIQUE KEY username (username),
    KEY department_id (department_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Sessions table (vulnerable session management)
CREATE TABLE user_sessions (
    session_id VARCHAR(128) NOT NULL,
    user_id INT(11) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    data TEXT, -- Serialized session data (deserialization vuln)
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id),
    KEY user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- OAuth tokens (vulnerable token storage)
CREATE TABLE oauth_tokens (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11) NOT NULL,
    client_id VARCHAR(100),
    access_token VARCHAR(500), -- Tokens stored in plain text
    refresh_token VARCHAR(500),
    scope TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- HUMAN RESOURCES MODULE
-- ===================================

CREATE TABLE departments (
    id INT(11) NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    manager_id INT(11),
    budget DECIMAL(15,2),
    description TEXT, -- XSS vulnerability
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY manager_id (manager_id),
    FOREIGN KEY (manager_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE employees (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11) NOT NULL,
    employee_id VARCHAR(20) UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    address TEXT,
    hire_date DATE,
    birth_date DATE, -- PII exposure
    salary DECIMAL(10,2), -- Sensitive data
    bank_account VARCHAR(50), -- Financial PII
    tax_id VARCHAR(20), -- Tax information
    emergency_contact_name VARCHAR(100),
    emergency_contact_phone VARCHAR(20),
    notes TEXT, -- Stored XSS vulnerability
    status ENUM('active','inactive','terminated') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY employee_id (employee_id),
    KEY user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Payroll with financial vulnerabilities
CREATE TABLE payroll (
    id INT(11) NOT NULL AUTO_INCREMENT,
    employee_id INT(11) NOT NULL,
    pay_period_start DATE,
    pay_period_end DATE,
    base_salary DECIMAL(10,2),
    overtime_hours DECIMAL(5,2),
    overtime_rate DECIMAL(10,2),
    bonus DECIMAL(10,2) DEFAULT 0, -- Business logic vuln
    deductions DECIMAL(10,2) DEFAULT 0,
    gross_pay DECIMAL(10,2),
    tax_withheld DECIMAL(10,2),
    net_pay DECIMAL(10,2),
    -- Calculation vulnerabilities for business logic testing
    calculation_notes TEXT,
    processed_by INT(11),
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY employee_id (employee_id),
    KEY processed_by (processed_by),
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    FOREIGN KEY (processed_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- E-COMMERCE MODULE
-- ===================================

CREATE TABLE categories (
    id INT(11) NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT, -- XSS vulnerability
    parent_id INT(11),
    image_url VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY parent_id (parent_id),
    FOREIGN KEY (parent_id) REFERENCES categories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE products (
    id INT(11) NOT NULL AUTO_INCREMENT,
    sku VARCHAR(50) UNIQUE,
    name VARCHAR(200) NOT NULL,
    description TEXT, -- XSS vulnerability
    category_id INT(11),
    price DECIMAL(10,2) NOT NULL,
    cost DECIMAL(10,2), -- Business sensitive data
    inventory_count INT DEFAULT 0,
    min_stock_level INT DEFAULT 0,
    weight DECIMAL(8,2),
    dimensions VARCHAR(50),
    images TEXT, -- JSON array, potential injection
    specifications TEXT, -- JSON data, vulnerable to injection
    tags TEXT, -- Comma-separated, searchable
    is_active BOOLEAN DEFAULT TRUE,
    featured BOOLEAN DEFAULT FALSE,
    discount_price DECIMAL(10,2), -- Price manipulation vulnerability
    discount_start DATETIME,
    discount_end DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY sku (sku),
    KEY category_id (category_id),
    KEY price (price),
    KEY is_active (is_active),
    FOREIGN KEY (category_id) REFERENCES categories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE shopping_carts (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11),
    session_id VARCHAR(128), -- Can be manipulated
    product_id INT(11) NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    price DECIMAL(10,2), -- Price can be manipulated
    discount_applied DECIMAL(10,2) DEFAULT 0, -- Business logic vuln
    custom_options TEXT, -- JSON data, injection risk
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY session_id (session_id),
    KEY product_id (product_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Orders with business logic vulnerabilities
CREATE TABLE orders (
    id INT(11) NOT NULL AUTO_INCREMENT,
    order_number VARCHAR(50) UNIQUE,
    user_id INT(11),
    status ENUM('pending','confirmed','processing','shipped','delivered','cancelled') DEFAULT 'pending',
    subtotal DECIMAL(10,2),
    tax_amount DECIMAL(10,2),
    shipping_amount DECIMAL(10,2),
    discount_amount DECIMAL(10,2) DEFAULT 0, -- Can be manipulated
    total_amount DECIMAL(10,2),
    -- Payment information (vulnerable storage)
    payment_method VARCHAR(50),
    payment_status ENUM('pending','paid','failed','refunded') DEFAULT 'pending',
    payment_reference VARCHAR(100),
    credit_card_last4 VARCHAR(4), -- PII exposure
    -- Shipping information
    shipping_first_name VARCHAR(50),
    shipping_last_name VARCHAR(50),
    shipping_address1 VARCHAR(200),
    shipping_address2 VARCHAR(200),
    shipping_city VARCHAR(100),
    shipping_state VARCHAR(50),
    shipping_zip VARCHAR(20),
    shipping_country VARCHAR(50),
    -- Billing information
    billing_first_name VARCHAR(50),
    billing_last_name VARCHAR(50),
    billing_address1 VARCHAR(200),
    billing_address2 VARCHAR(200),
    billing_city VARCHAR(100),
    billing_state VARCHAR(50),
    billing_zip VARCHAR(20),
    billing_country VARCHAR(50),
    -- Metadata
    notes TEXT, -- XSS vulnerability
    admin_notes TEXT, -- Internal notes
    shipped_at DATETIME,
    delivered_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY order_number (order_number),
    KEY user_id (user_id),
    KEY status (status),
    KEY payment_status (payment_status),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE order_items (
    id INT(11) NOT NULL AUTO_INCREMENT,
    order_id INT(11) NOT NULL,
    product_id INT(11) NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10,2) NOT NULL, -- Historical price
    discount DECIMAL(10,2) DEFAULT 0,
    total DECIMAL(10,2) NOT NULL,
    product_data TEXT, -- JSON snapshot, injection risk
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY order_id (order_id),
    KEY product_id (product_id),
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- FINANCIAL MODULE
-- ===================================

CREATE TABLE accounts (
    id INT(11) NOT NULL AUTO_INCREMENT,
    account_number VARCHAR(50) UNIQUE,
    account_name VARCHAR(100),
    account_type ENUM('asset','liability','equity','income','expense'),
    parent_id INT(11),
    balance DECIMAL(15,2) DEFAULT 0,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY account_number (account_number),
    KEY parent_id (parent_id),
    FOREIGN KEY (parent_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE transactions (
    id INT(11) NOT NULL AUTO_INCREMENT,
    transaction_id VARCHAR(50) UNIQUE,
    reference_number VARCHAR(100),
    description TEXT, -- XSS vulnerability
    debit_account_id INT(11),
    credit_account_id INT(11),
    amount DECIMAL(15,2) NOT NULL,
    transaction_date DATE,
    created_by INT(11),
    approved_by INT(11),
    status ENUM('draft','pending','approved','cancelled') DEFAULT 'draft',
    notes TEXT, -- Additional XSS vulnerability
    metadata TEXT, -- JSON data for injection
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY transaction_id (transaction_id),
    KEY debit_account_id (debit_account_id),
    KEY credit_account_id (credit_account_id),
    KEY created_by (created_by),
    KEY approved_by (approved_by),
    KEY transaction_date (transaction_date),
    FOREIGN KEY (debit_account_id) REFERENCES accounts(id),
    FOREIGN KEY (credit_account_id) REFERENCES accounts(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Invoices with business logic vulnerabilities
CREATE TABLE invoices (
    id INT(11) NOT NULL AUTO_INCREMENT,
    invoice_number VARCHAR(50) UNIQUE,
    customer_id INT(11),
    invoice_date DATE,
    due_date DATE,
    subtotal DECIMAL(12,2),
    tax_rate DECIMAL(5,4),
    tax_amount DECIMAL(12,2),
    discount_amount DECIMAL(12,2) DEFAULT 0, -- Can be manipulated
    total_amount DECIMAL(12,2),
    paid_amount DECIMAL(12,2) DEFAULT 0,
    status ENUM('draft','sent','paid','overdue','cancelled') DEFAULT 'draft',
    notes TEXT, -- XSS vulnerability
    terms TEXT,
    created_by INT(11),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY invoice_number (invoice_number),
    KEY customer_id (customer_id),
    KEY created_by (created_by),
    KEY status (status),
    FOREIGN KEY (customer_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- CRM MODULE  
-- ===================================

CREATE TABLE customers (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11),
    company_name VARCHAR(200),
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    phone VARCHAR(20),
    website VARCHAR(255),
    industry VARCHAR(100),
    annual_revenue DECIMAL(15,2), -- Sensitive business data
    employee_count INT,
    address TEXT,
    city VARCHAR(100),
    state VARCHAR(50),
    zip VARCHAR(20),
    country VARCHAR(50),
    lead_source VARCHAR(100),
    lead_status ENUM('new','contacted','qualified','proposal','negotiation','won','lost'),
    assigned_to INT(11), -- Sales rep
    notes TEXT, -- XSS vulnerability
    tags TEXT, -- Searchable tags
    last_contact_date DATETIME,
    next_followup_date DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY assigned_to (assigned_to),
    KEY lead_status (lead_status),
    KEY email (email),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- FILE UPLOAD & DOCUMENT MANAGEMENT
-- ===================================

CREATE TABLE file_uploads (
    id INT(11) NOT NULL AUTO_INCREMENT,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255),
    file_path VARCHAR(500), -- Path traversal vulnerability
    file_size INT,
    file_type VARCHAR(100), -- MIME type, can be spoofed
    uploaded_by INT(11),
    is_public BOOLEAN DEFAULT FALSE,
    access_token VARCHAR(100), -- Weak file access tokens
    description TEXT, -- XSS vulnerability
    tags TEXT,
    virus_scanned BOOLEAN DEFAULT FALSE,
    scan_result TEXT,
    download_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY uploaded_by (uploaded_by),
    KEY file_type (file_type),
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- SYSTEM LOGS & AUDIT TRAIL
-- ===================================

CREATE TABLE audit_logs (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11),
    action VARCHAR(100),
    table_name VARCHAR(100),
    record_id INT(11),
    old_values TEXT, -- JSON data, potential injection
    new_values TEXT, -- JSON data, potential injection
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY action (action),
    KEY table_name (table_name),
    KEY timestamp (timestamp),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Error logs for information disclosure
CREATE TABLE error_logs (
    id INT(11) NOT NULL AUTO_INCREMENT,
    error_level ENUM('debug','info','warning','error','critical'),
    message TEXT,
    context TEXT, -- JSON context, potential sensitive data leak
    stack_trace TEXT, -- Full stack traces exposed
    user_id INT(11),
    ip_address VARCHAR(45),
    request_data TEXT, -- Full request data including sensitive info
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY error_level (error_level),
    KEY user_id (user_id),
    KEY created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- CONFIGURATION & SETTINGS
-- ===================================

CREATE TABLE system_settings (
    id INT(11) NOT NULL AUTO_INCREMENT,
    setting_key VARCHAR(100) UNIQUE,
    setting_value TEXT, -- Can contain sensitive configuration
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE, -- Indicates if value should be encrypted (but isn't)
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY setting_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- API keys table (vulnerable key management)
CREATE TABLE api_keys (
    id INT(11) NOT NULL AUTO_INCREMENT,
    key_name VARCHAR(100),
    api_key VARCHAR(255), -- Plain text API keys
    secret_key VARCHAR(255), -- Plain text secrets
    user_id INT(11),
    permissions TEXT, -- JSON permissions
    rate_limit INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at DATETIME,
    expires_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY api_key (api_key),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- SEARCH & ANALYTICS
-- ===================================

-- Search queries for injection testing
CREATE TABLE search_queries (
    id INT(11) NOT NULL AUTO_INCREMENT,
    user_id INT(11),
    query_text TEXT, -- Raw search queries, injection risk
    results_count INT,
    search_type VARCHAR(50),
    filters TEXT, -- JSON filters, injection risk
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY search_type (search_type),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ===================================
-- INDEXES FOR PERFORMANCE & INJECTION TESTING
-- ===================================

-- Additional indexes for common injection points
CREATE INDEX idx_users_username_password ON users(username, password);
CREATE INDEX idx_products_name_description ON products(name, description(100));
CREATE INDEX idx_orders_total_status ON orders(total_amount, status);
CREATE INDEX idx_audit_logs_composite ON audit_logs(user_id, action, timestamp);

-- Vulnerable full-text search indexes
ALTER TABLE products ADD FULLTEXT(name, description, tags);
ALTER TABLE customers ADD FULLTEXT(company_name, notes);
ALTER TABLE search_queries ADD FULLTEXT(query_text);

