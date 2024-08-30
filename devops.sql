-- 1. Create database devops
CREATE DATABASE devops;

-- 2. Switch to the devops database
USE devops;

-- 3. Create table users
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(30) NOT NULL
);

-- 4. Insert 3 rows into users table
INSERT INTO users (id, name) VALUES 
(1, 'User 1'),
(2, 'User 2'),
(3, 'User 3');
