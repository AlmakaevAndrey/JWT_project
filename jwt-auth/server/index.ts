import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import express from "express";
import {Request, Response} from "express";
import jwt, {JwtPayload} from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true}));
app.use(express.json());
app.use(cookieParser());

interface User {
    id: number,
    username: string,
    password: string,
}

interface TokenPayload {
    id: number,
}

const users: User[] = [
    {id: 1, username: "admin", password: "1234"}
];

let refreshTokensArray: string[] = [];

function isTokenPayload(payload: unknown): payload is TokenPayload {
  return typeof payload === "object" && payload !== null && "id" in payload;
}

const generateAccessToken = (user: TokenPayload) => {
    return jwt.sign(user, process.env.ACCESS_SECRET as string, { expiresIn: "5m" });
};

const generateRefreshToken = (user: TokenPayload) => {
    const token = jwt.sign(user, process.env.REFRESH_SECRET as string, { expiresIn: "3d" });
    refreshTokensArray.push(token);
    return token;
}

app.post("/login", (req: Request, res: Response) => {
    try {
        const { username, password } = req.body as {username: string; password: string};
    
        const user = users.find(u => u.username === username && u.password === password);
        if (!user) return res.status(401).json({ message: "Invalid data"});
    
        const accessToken = generateAccessToken({ id: user.id });
        const refreshToken = generateRefreshToken({ id: user.id });
    
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
        })
        res.json({accessToken});
    } catch (error) {
        console.error("Login error", error);
        res.status(501).json({ message: "Internal server error" });
    }
})

app.post("/refresh", (req: Request, res: Response) => {
    const oldToken = req.cookies.refreshToken;
    if (!oldToken || !refreshTokensArray.includes(oldToken)) return res.sendStatus(403);

    jwt.verify(oldToken, process.env.REFRESH_SECRET as string, (err: any, decoded: unknown) => {
        if (err || !isTokenPayload(decoded)) return res.sendStatus(403);
        const {id} = decoded

        refreshTokensArray = refreshTokensArray.filter(t => t !== oldToken);

        const newAccessToken = generateAccessToken({ id });
        const newRefreshToken = generateRefreshToken({ id });

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({accessToken: newAccessToken});
    });
});

app.post("/logout", (req: Request, res: Response) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.sendStatus(204);

    refreshTokensArray = refreshTokensArray.filter(t => t !== token);
    res.clearCookie("refreshToken");
    res.sendStatus(204);
})

app.get("/protected", (req: Request, res: Response) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_SECRET as string, (err, user) => {
        if (err || typeof user !== "object" || user === null || !("id" in user)) return res.sendStatus(403);

        res.json({message: "Protected content", user});
    });
});

app.listen(8000, () => {
    console.log("Server running on http://localhost:8000");
});

