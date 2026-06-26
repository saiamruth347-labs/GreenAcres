-- ─────────────────────────────────────────────
-- Users (main accounts)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(120) NOT NULL,
    username      VARCHAR(60)  NOT NULL UNIQUE,
    email         VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    -- Profile details
    title         VARCHAR(180),               -- e.g. "Organic Wheat Farmer"
    location      VARCHAR(200),
    bio           TEXT,
    avatar_url    VARCHAR(500) DEFAULT '',
    cover_url     VARCHAR(500) DEFAULT '',
    clerk_id      VARCHAR(255) UNIQUE DEFAULT NULL,
    -- Social stats (denormalized for speed)
    connections   INT UNSIGNED DEFAULT 0,
    posts_count   INT UNSIGNED DEFAULT 0,
    -- Status
    is_active     TINYINT(1) DEFAULT 1,
    is_verified   TINYINT(1) DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login    TIMESTAMP NULL
);

-- ── Connections / Followers ────────────────────────────
CREATE TABLE IF NOT EXISTS connections (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    requester_id INT NOT NULL,
    receiver_id  INT NOT NULL,
    status       ENUM('pending','accepted','blocked') DEFAULT 'pending',
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_conn (requester_id, receiver_id),
    FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id)  REFERENCES users(id) ON DELETE CASCADE
);

-- ── Posts (community feed) ─────────────────────────────
CREATE TABLE IF NOT EXISTS posts (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    content    TEXT NOT NULL,
    media_url  VARCHAR(500) DEFAULT NULL,   -- optional photo/video URL
    post_type  ENUM('update','weather','tool_request','crop_report') DEFAULT 'update',
    likes      INT UNSIGNED DEFAULT 0,
    comments   INT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── Post Likes ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS post_likes (
    user_id    INT NOT NULL,
    post_id    INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id)  ON DELETE CASCADE
);

-- ── Post Comments ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS post_comments (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    post_id    INT NOT NULL,
    user_id    INT NOT NULL,
    content    TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id)  REFERENCES posts(id)  ON DELETE CASCADE,
    FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
);

-- ── Messages (chat) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sender_id   INT NOT NULL,
    receiver_id INT NOT NULL,
    content     TEXT NOT NULL,
    is_read     TINYINT(1) DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_conversation (sender_id, receiver_id),
    INDEX idx_receiver_unread (receiver_id, is_read)
);

-- ── Market Listings ───────────────────────────────────
CREATE TABLE IF NOT EXISTS market_listings (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    seller_id    INT NOT NULL,
    title        VARCHAR(200) NOT NULL,
    description  TEXT,
    category     ENUM('tractor','fertilizer','ghee','grain','crop','other') NOT NULL,
    listing_type ENUM('sell','rent') DEFAULT 'sell',
    price        DECIMAL(12,2) NOT NULL,
    price_unit   VARCHAR(50) DEFAULT '',    -- e.g. "/kg", "/day", "/quintal"
    location     VARCHAR(200),
    contact_phone VARCHAR(20) DEFAULT '',
    image_url    VARCHAR(500) DEFAULT '',
    status       ENUM('active','sold','expired') DEFAULT 'active',
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_category (category),
    INDEX idx_status   (status)
);

-- ── JWT Token Blocklist (for logout) ─────────────────
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        VARCHAR(36) PRIMARY KEY,   -- JWT ID (uuid)
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Market Bookings ──────────────────────────────────
CREATE TABLE IF NOT EXISTS market_bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    seller_id INT NOT NULL,
    listing_id INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(listing_id) REFERENCES market_listings(id) ON DELETE CASCADE
);

-- ════════════════════════════════════════
--   Seed Data
-- ════════════════════════════════════════
-- Default admin / demo farmer account  (password: farmer123)
INSERT IGNORE INTO users
    (full_name, username, email, password_hash, title, location, bio, avatar_url, connections)
VALUES
    ('Organic Farmer',
     'demo_farmer',
     'demo@agriconnect.in',
     '26c07fc7be1668f8ea7e3801d4ffdbf33de487a593a69028936ec49f2c89f6ab',

     'Organic Farmer & Agri-Tech Enthusiast',
     'Andhra Pradesh, India',
     'Passionate about sustainable farming and agri-technology. Sharing knowledge with fellow farmers.',
     'https://ui-avatars.com/api/?name=O+F&background=1b873f&color=fff&rounded=true',
     342);

INSERT IGNORE INTO users
    (full_name, username, email, password_hash, title, location, bio, avatar_url, connections)
VALUES
    ('Rajesh Kumar',
     'rajesh_farmer',
     'rajesh@agriconnect.in',
     '26c07fc7be1668f8ea7e3801d4ffdbf33de487a593a69028936ec49f2c89f6ab',

     'Traditional Wheat Farmer',
     'Punjab, India',
     'Third generation wheat farmer from Punjab. I swear by drip irrigation!',
     'https://ui-avatars.com/api/?name=R+K&background=d4edda&color=1b5e20&rounded=true',
     120);

INSERT IGNORE INTO posts (user_id, content, likes, comments) VALUES
(2, 'Just finished testing the new drip irrigation system on the north field. The water savings are incredible! Highly recommend this to anyone dealing with the current dry spell. Happy to share the installation guide if anyone needs it. 🌾💧', 124, 18),
(1, 'Started using neem oil spray on my crops this season instead of chemical pesticides. The results are amazing – pests are down 70% and my veggies look healthier than ever! 🌿✨', 89, 12);

INSERT IGNORE INTO market_listings (seller_id, title, category, listing_type, price, price_unit, location, image_url, description) VALUES
(2, 'Mahindra JIVO 245 DI Tractor', 'tractor', 'rent', 1800, '/day', 'Punjab, India', '/static/agri/Mahindra JIVO 245 DI Tractor.avif', 'High performance compact tractor for small farms. 4WD, 24HP, 2023 Model.'),
(1, 'Pure Desi Cow Ghee (1L)', 'ghee', 'sell', 850, '/litre', 'Andhra Pradesh, India', '/static/agri/Pure Desi Cow Ghee (1L).webp', 'Traditional A2 Cow Ghee. No additives, purely handcrafted.');
