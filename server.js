
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, "users.json");

// تنظیمات اولیه
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// تنظیمات نشست کاربران
app.use(session({
    secret: process.env.SESSION_SECRET || "pikso-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: "auto",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// نمایش صفحات سایت از پوشه public
app.use(express.static(path.join(__dirname, "public")));

// دریافت کاربران
function getUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            fs.writeFileSync(USERS_FILE, "[]", "utf8");
        }

        const data = fs.readFileSync(USERS_FILE, "utf8");
        const users = JSON.parse(data);

        return Array.isArray(users) ? users : [];
    } catch (error) {
        console.error("Users error:", error);
        return [];
    }
}

// ذخیره کاربران
function saveUsers(users) {
    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify(users, null, 2),
        "utf8"
    );
}

// بررسی فعال بودن سرور
app.get("/api", (req, res) => {
    res.json({
        message: "PIKSO GAMES SERVER IS RUNNING!"
    });
});

// ثبت نام
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "اطلاعات نامعتبر است."
            });
        }

        const cleanUsername = username.trim();

        if (cleanUsername.length < 3 || cleanUsername.length > 20) {
            return res.status(400).json({
                message: "نام کاربری باید بین ۳ تا ۲۰ کاراکتر باشد."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "رمز عبور باید حداقل ۶ کاراکتر باشد."
            });
        }

        const users = getUsers();

        const exists = users.some(
            user => user.username.toLowerCase() === cleanUsername.toLowerCase()
        );

        if (exists) {
            return res.status(409).json({
                message: "این نام کاربری قبلاً ثبت شده است."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        users.push({
            username: cleanUsername,
            password: hashedPassword
        });

        saveUsers(users);

        return res.status(201).json({
            message: "ثبت‌نام موفق بود! حالا وارد شو."
        });

    } catch (error) {
        console.error("Register error:", error);

        return res.status(500).json({
            message: "خطای سرور در ثبت‌نام."
        });
    }
});

// ورود
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "اطلاعات نامعتبر است."
            });
        }

        const users = getUsers();

        const user = users.find(
            item => item.username.toLowerCase() === username.trim().toLowerCase()
        );

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({
                message: "نام کاربری یا رمز عبور اشتباه است."
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                console.error(error);

                return res.status(500).json({
                    message: "خطا در ایجاد نشست کاربری."
                });
            }

            req.session.username = user.username;

            req.session.save((saveError) => {
                if (saveError) {
                    console.error(saveError);

                    return res.status(500).json({
                        message: "خطا در ذخیره ورود."
                    });
                }

                return res.json({
                    message: "ورود موفق بود!",
                    redirect: "/dashboard.html"
                });
            });
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            message: "خطای سرور در ورود."
        });
    }
});

// اطلاعات حساب کاربری
app.get("/api/me", (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({
            message: "وارد حساب نشده‌اید."
        });
    }

    res.json({
        username: req.session.username
    });
});

// خروج از حساب
app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error(error);

            return res.status(500).json({
                message: "خطا در خروج."
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            message: "با موفقیت خارج شدید."
        });
    });
});

// مدیریت خطاهای سرور
app.use((error, req, res, next) => {
    console.error(error);

    res.status(500).json({
        message: "خطای داخلی سرور."
    });
});

// اجرای سرور
app.listen(PORT, "0.0.0.0", () => {
    console.log("================================");
    console.log("PIKSO GAMES SERVER IS RUNNING");
    console.log("PORT: " + PORT);
    console.log("================================");
});
