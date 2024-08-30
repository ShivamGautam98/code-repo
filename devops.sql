-- 1. Create database devops if it does not exist
CREATE DATABASE IF NOT EXISTS devops;

-- 2. Switch to the devops database
USE devops;

-- 3. Create table users if it does not exist
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(30) NOT NULL
);

-- 4. Insert 3 rows into users table if they do not already exist
INSERT IGNORE INTO users (id, name) VALUES 
(1, 'User 1'),
(2, 'User 2'),
(3, 'User 3');
