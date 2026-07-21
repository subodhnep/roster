-- Roster Availability Database (Postgres / Neon version)
-- Run this in Neon's SQL Editor (Neon dashboard -> your project -> SQL Editor)
-- Paste the whole thing in and run it once.

CREATE TABLE IF NOT EXISTS departments (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE
);
INSERT INTO departments (name) VALUES ('Liquor'), ('Grocery')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS locations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE
);
INSERT INTO locations (name) VALUES ('Karabar'), ('Kaleen')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS staff (
  id SERIAL PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  departments VARCHAR(255) NOT NULL,          -- comma-separated, e.g. "Liquor,Grocery"
  location VARCHAR(100) NOT NULL DEFAULT '',  -- e.g. "Karabar" or "Kaleen"
  code VARCHAR(20) NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT NOW()
);
INSERT INTO staff (name, departments, location, code)
  VALUES ('Test Staff', 'Grocery', 'Karabar', 'TEST01')
  ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS availability (
  id SERIAL PRIMARY KEY,
  staff_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
  week_start DATE NOT NULL,       -- always a Monday
  day VARCHAR(10) NOT NULL,       -- Monday..Sunday
  available BOOLEAN NOT NULL DEFAULT FALSE,
  start_time VARCHAR(5),
  end_time VARCHAR(5),
  submitted_at TIMESTAMP DEFAULT NOW(),
  UNIQUE (staff_id, week_start, day)
);

CREATE TABLE IF NOT EXISTS settings (
  setting_key VARCHAR(50) PRIMARY KEY,
  setting_value VARCHAR(255) NOT NULL
);
-- Admin password (admin123 by default) and the window-override setting
-- are created automatically the first time the site loads.
