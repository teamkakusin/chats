const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_by INT REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      room_id INT REFERENCES rooms(id) ON DELETE CASCADE,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  next();
}

async function getUserById(id) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return result.rows[0] || null;
}

async function getCurrentRoom(req) {
  if (!req.session.roomId) return null;
  const result = await pool.query("SELECT * FROM rooms WHERE id = $1", [req.session.roomId]);
  return result.rows[0] || null;
}

async function getRoomPosts(roomId) {
  const result = await pool.query(`
    SELECT p.*, u.username
    FROM posts p
    JOIN users u ON u.id = p.user_id
    WHERE p.room_id = $1
    ORDER BY p.created_at DESC
    LIMIT 100
  `, [roomId]);
  return result.rows;
}

app.get("/", async (req, res) => {
  if (!req.session.userId) {
    return res.render("landing", {
      error: "",
      success: "",
      user: null,
      room: null,
      rooms: [],
      posts: [],
    });
  }

  const user = await getUserById(req.session.userId);
  const room = await getCurrentRoom(req);
  const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
  const posts = room ? await getRoomPosts(room.id) : [];

  res.render("dashboard", {
    user,
    room,
    rooms: roomsResult.rows,
    posts,
    error: "",
    success: "",
  });
});

app.post("/register", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "").trim();

  if (!username || !password) {
    return res.render("landing", {
      error: "ID とパスワードを入力してください。",
      success: "",
      user: null,
      room: null,
      rooms: [],
      posts: [],
    });
  }

  const exists = await pool.query("SELECT 1 FROM users WHERE username = $1", [username]);
  if (exists.rowCount > 0) {
    return res.render("landing", {
      error: "そのIDはすでに使われています。",
      success: "",
      user: null,
      room: null,
      rooms: [],
      posts: [],
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
    [username, passwordHash]
  );

  req.session.userId = result.rows[0].id;
  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "").trim();

  const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  const user = result.rows[0];

  if (!user) {
    return res.render("landing", {
      error: "ユーザーが見つかりません。",
      success: "",
      user: null,
      room: null,
      rooms: [],
      posts: [],
    });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.render("landing", {
      error: "パスワードが違います。",
      success: "",
      user: null,
      room: null,
      rooms: [],
      posts: [],
    });
  }

  req.session.userId = user.id;
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.post("/room/create", requireLogin, async (req, res) => {
  const name = (req.body.name || "").trim();
  const password = (req.body.password || "").trim();

  if (!name || !password) {
    const user = await getUserById(req.session.userId);
    const room = await getCurrentRoom(req);
    const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
    const posts = room ? await getRoomPosts(room.id) : [];

    return res.render("dashboard", {
      user,
      room,
      rooms: roomsResult.rows,
      posts,
      error: "ルーム名とパスワードを入力してください。",
      success: "",
    });
  }

  const existing = await pool.query("SELECT 1 FROM rooms WHERE name = $1", [name]);
  if (existing.rowCount > 0) {
    const user = await getUserById(req.session.userId);
    const room = await getCurrentRoom(req);
    const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
    const posts = room ? await getRoomPosts(room.id) : [];

    return res.render("dashboard", {
      user,
      room,
      rooms: roomsResult.rows,
      posts,
      error: "そのルーム名はすでに存在します。",
      success: "",
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO rooms (name, password_hash, created_by) VALUES ($1, $2, $3) RETURNING *",
    [name, passwordHash, req.session.userId]
  );

  req.session.roomId = result.rows[0].id;
  res.redirect("/");
});

app.post("/room/join", requireLogin, async (req, res) => {
  const name = (req.body.name || "").trim();
  const password = (req.body.password || "").trim();

  const result = await pool.query("SELECT * FROM rooms WHERE name = $1", [name]);
  const room = result.rows[0];

  if (!room) {
    const user = await getUserById(req.session.userId);
    const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
    return res.render("dashboard", {
      user,
      room: await getCurrentRoom(req),
      rooms: roomsResult.rows,
      posts: [],
      error: "そのルームは存在しません。",
      success: "",
    });
  }

  const ok = await bcrypt.compare(password, room.password_hash);
  if (!ok) {
    const user = await getUserById(req.session.userId);
    const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
    return res.render("dashboard", {
      user,
      room: await getCurrentRoom(req),
      rooms: roomsResult.rows,
      posts: [],
      error: "ルームのパスワードが違います。",
      success: "",
    });
  }

  req.session.roomId = room.id;
  res.redirect("/");
});

app.get("/switch-room/:id", requireLogin, async (req, res) => {
  const roomId = Number(req.params.id);
  const result = await pool.query("SELECT * FROM rooms WHERE id = $1", [roomId]);
  const room = result.rows[0];

  if (!room) {
    return res.redirect("/");
  }

  req.session.roomId = room.id;
  res.redirect("/");
});

app.post("/post", requireLogin, async (req, res) => {
  const room = await getCurrentRoom(req);
  if (!room) {
    const user = await getUserById(req.session.userId);
    return res.render("dashboard", {
      user,
      room: null,
      rooms: [],
      posts: [],
      error: "先にルームに入ってください。",
      success: "",
    });
  }

  const content = (req.body.content || "").trim();
  if (!content) {
    const user = await getUserById(req.session.userId);
    const roomsResult = await pool.query("SELECT * FROM rooms ORDER BY created_at DESC");
    const posts = await getRoomPosts(room.id);

    return res.render("dashboard", {
      user,
      room,
      rooms: roomsResult.rows,
      posts,
      error: "投稿内容を入力してください。",
      success: "",
    });
  }

  const safeContent = content.slice(0, 280);
  await pool.query(
    "INSERT INTO posts (room_id, user_id, content) VALUES ($1, $2, $3)",
    [room.id, req.session.userId, safeContent]
  );

  res.redirect("/");
});

initializeDatabase()
  .then(() => {
    app.listen(port, () => {
      console.log(`App listening on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("DB init failed:", err);
    process.exit(1);
  });
