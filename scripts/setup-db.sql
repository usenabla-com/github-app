-- Database setup script for Nabla GitHub App
-- Run this to create the initial database structure

-- Create database (run this manually as superuser)
-- CREATE DATABASE nabla;

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Customers table
CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    events JSONB DEFAULT '[]'::jsonb,
    features JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- GitHub Apps table (supports multiple apps for different instances)
CREATE TABLE IF NOT EXISTS github_apps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id BIGINT NOT NULL,
    private_key TEXT NOT NULL,
    github_api_base TEXT NOT NULL,
    webhook_secret TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(app_id, github_api_base)
);

-- GitHub Installations table
CREATE TABLE IF NOT EXISTS github_installations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    github_app_id UUID NOT NULL REFERENCES github_apps(id),
    installation_id BIGINT NOT NULL,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,
    permissions JSONB,
    events JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    suspended_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(github_app_id, installation_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_customers_github_login ON customers(github_account_login);
CREATE INDEX IF NOT EXISTS idx_installations_installation_id ON github_installations(installation_id);
CREATE INDEX IF NOT EXISTS idx_installations_account_login ON github_installations(account_login);
CREATE INDEX IF NOT EXISTS idx_installations_suspended ON github_installations(suspended_at) WHERE suspended_at IS NULL;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_customers_updated_at BEFORE UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_github_apps_updated_at BEFORE UPDATE ON github_apps FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();