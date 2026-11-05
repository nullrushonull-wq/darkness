
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "pikso-local-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, "public")));

const dbPath = path.join(__dirname, "users.json");

function getUsers() {
    if (!fs.existsSync(dbPath)) {
        fs.writeFileSync(dbPath, "[]", "utf8");
    }
    return JSON.parse(fs.readFileSync(dbPath, "utf8"));
}

function saveUsers(users) {
    fs.writeFileSync(dbPath, JSON.stringify(users, null, 2), "utf8");
}

// ثبت نام
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({ message: "اطلاعات نامعتبر است" });
        }

        const cleanUsername = username.trim();

        if (cleanUsername.length < 3 || cleanUsername.length > 20 ||
            password.length < 8 || password.length > 128) {
            return res.status(400).json({
                message: "نام کاربری باید ۳ تا ۲۰ و رمز حداقل ۸ کاراکتر باشد"
            });
        }

        const users = getUsers();

        if (users.some(u => u.username.toLowerCase() === cleanUsername.toLowerCase())) {
            return res.status(409).json({ message: "این نام کاربری قبلاً ثبت شده است" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        users.push({
            username: cleanUsername,
            password: hashedPassword
        });

        saveUsers(users);

        res.status(201).json({ message: "ثبت نام موفق بود! حالا وارد شو." });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "خطای سرور در ثبت نام" });
    }
});

// ورود
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({ message: "اطلاعات نامعتبر است" });
        }

        const users = getUsers();

        const user = users.find(
            u => u.username.toLowerCase() === username.trim().toLowerCase()
        );

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({
                message: "نام کاربری یا رمز عبور اشتباه است"
            });
        }

        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ message: "خطا در ایجاد نشست کاربری" });
            }

            req.session.username = user.username;

            req.session.save((saveError) => {
                if (saveError) {
                    return res.status(500).json({ message: "خطا در ذخیره ورود" });
                }

                res.json({
                    message: "ورود موفق بود",
                    redirect: "dashboard.html"
                });
            });
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "خطای سرور در ورود" });
    }
});

// اطلاعات حساب
app.get("/api/me", (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ message: "وارد حساب نشده‌اید" });
    }

    res.json({ username: req.session.username });
});

// خروج
app.post("/api/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: "خطا در خروج" });
        }

        res.clearCookie("connect.sid");
        res.json({ message: "با موفقیت خارج شدید" });
    });
});

// صفحه اصلی API
app.get("/api", (req, res) => {
    res.send("PIKSO GAMES SERVER IS RUNNING!");
});

app.listen(PORT, () => {
    console.log("================================");
    console.log("PIKSO GAMES SERVER IS RUNNING");
    console.log("http://localhost:" + PORT);
    console.log("================================");
});
