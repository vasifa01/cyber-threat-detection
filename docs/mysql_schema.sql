-- MySQL schema for the AI Cyber Threat Detection System.
-- The backend creates these tables automatically on startup (SQLAlchemy),
-- this file documents them and lets you create them by hand if preferred.
--
--   mysql -u root -p < docs/mysql_schema.sql
--   export DATABASE_URL="mysql+pymysql://threat_user:change-me@localhost:3306/threatdb"

CREATE DATABASE IF NOT EXISTS threatdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'threat_user'@'localhost' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON threatdb.* TO 'threat_user'@'localhost';
USE threatdb;

-- Every analysed input (a network flow or a URL)
CREATE TABLE IF NOT EXISTS events (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  source      VARCHAR(20) NOT NULL,          -- 'traffic' | 'url'
  source_ip   VARCHAR(45) NULL,
  payload     TEXT NOT NULL,                 -- JSON features or the URL
  dropped     BOOLEAN NOT NULL DEFAULT FALSE,-- source IP was already blocked
  created_at  DATETIME NOT NULL,
  INDEX ix_events_source (source),
  INDEX ix_events_source_ip (source_ip),
  INDEX ix_events_created_at (created_at)
);

-- What the ML model decided for each event
CREATE TABLE IF NOT EXISTS detections (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  event_id    INT NOT NULL UNIQUE,
  model       VARCHAR(50) NOT NULL,
  label       VARCHAR(30) NOT NULL,          -- Normal, DoS, Probe, R2L, U2R, Anomaly, Benign, Phishing, Malware
  confidence  FLOAT NOT NULL,
  is_threat   BOOLEAN NOT NULL,
  anomaly     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  DATETIME NOT NULL,
  FOREIGN KEY (event_id) REFERENCES events(id),
  INDEX ix_detections_label (label),
  INDEX ix_detections_is_threat (is_threat),
  INDEX ix_detections_created_at (created_at)
);

-- Raised for every threat
CREATE TABLE IF NOT EXISTS alerts (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  detection_id  INT NOT NULL UNIQUE,
  severity      VARCHAR(10) NOT NULL,        -- Low | Medium | High | Critical
  status        VARCHAR(15) NOT NULL,        -- open | blocked | resolved
  action        VARCHAR(100) NULL,
  created_at    DATETIME NOT NULL,
  FOREIGN KEY (detection_id) REFERENCES detections(id),
  INDEX ix_alerts_severity (severity),
  INDEX ix_alerts_status (status),
  INDEX ix_alerts_created_at (created_at)
);

-- Simulated firewall
CREATE TABLE IF NOT EXISTS blocklist (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  ip          VARCHAR(45) NOT NULL UNIQUE,
  reason      VARCHAR(200) NOT NULL,
  created_at  DATETIME NOT NULL
);
