import express, { Express, Request, Response } from "express";
import { WebSocketServer, WebSocket, RawData } from "ws"
import { JwtPayload, sign, verify } from "jsonwebtoken"
import * as fs from "fs";
import * as crypto from "crypto";

interface obj {
    id: string;
    msg: string;
}

const app: Express = express();

const pv = fs.readFileSync("./src/server/pv.pem", "utf8");

const wss = new WebSocketServer({
    port: 3000,
});

app.use(express.json());

app.post("/ping", async (req: Request, res: Response) => {
    // Get AuthKey
    const ip: any = await req.headers["cf-connecting-ip"] || req.headers["X-Forwarded-For"] || "test" as const;
    const msg: string = req.body.msg;

    if (!ip || !msg) return res.status(403).json({ status: "403", content: "forbidden" });

    const msgobj = {
        id: crypto.createHash("md5").update(ip).digest("hex"),
        msg: msg
    }

    const token = sign(msgobj, pv, { algorithm: "RS256", expiresIn: "10s" });

    res.set("key", token)

    return res.end("pong!")

});

app.get("/ping", (req: Request, res: Response) => {
    return res.end("pong!");
});

const check = (str: RawData): boolean => {
    try {
        JSON.parse(str.toString());
    } catch (e) {
        return false;
    }
    return true;
}

const check2 = (obj: string | JwtPayload): boolean => {
    if (typeof obj === "string") {
        return false;
    } else {
        if (!obj.id || !obj.msg) {
            return false;
        } else {
            return true;
        }
    }
}

wss.on("connection", async (ws, req) => {
    ws.on("error", console.error);

    ws.on("message", async (data) => {

        // integrity check

        if (!(check(data))) {
            ws.send("Wrong Format! (113)");
            return ws.terminate();
        }

        const dataparse = JSON.parse(data.toString());
        if (!dataparse.key) {
            ws.send("Wrong Format! (114)");
            return ws.terminate();
        }


        try {
            const decoded = verify(dataparse.key, pv);

            console.log(decoded);

            if (!check2(decoded)) {
                ws.send("Wrong Format! (116)");
                return ws.terminate();
            }

            // send to all clients
            wss.clients.forEach(async (client) => {
                if (client.readyState === WebSocket.OPEN) {
                    if (typeof decoded !== "string") {
                        client.send(JSON.stringify({
                            id: decoded.id,
                            msg: decoded.msg
                        }));
                    } else {
                        return ws.terminate();
                    }
                }
            });

        } catch (err) {
            ws.send("Wrong Format! (115)");
            return ws.terminate();
        }

    });
});

app.listen(4000);
