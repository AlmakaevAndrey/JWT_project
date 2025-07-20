import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true}));
app.use(express.json());
app.use(cookieParser());

const users = [
    {id: 1, username: "admin", password: "1234"}
];

let refreshTokensArray = [];

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_SECRET, { expiresIn: "15s" });
};

const generateRefreshToken = (user) => {
    const token = jwt.sign(user, process.env.REFRESH_SECRET, { expiresIn: "7s" });
    refreshTokensArray.push(token);
    return token;
}

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ message: "Invalid data"});

    const accessToken = generateAccessToken({ id: user.id });
    const refreshToken = generateRefreshToken({ id: user.id });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
    })

    res.json({accessToken});
})

app.post("/refresh", (req, res) => {
    const token = req.cookies.refreshToken;
    if(!token || !refreshTokensArray.includes(token)) return res.sendStatus(403);

    jwt.verify(token, process.env.REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        const newAccessToken = generateAccessToken({ id: user.id });
        res.json({accessToken: newAccessToken});
    })
})

app.post("/logout", (req, res) => {
    refreshTokensArray = refreshTokensArray.filter(t => t !== req.cookies.refreshToken);
    res.clearCookie("refreshToken");
    res.sendStatus(204);
})

app.get("/protected", (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        res.json({message: "Protected content", user});
    });
});

app.listen(8000, () => {
    console.log("Server running on http://localhost:8000");
});

