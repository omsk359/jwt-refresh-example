import express from 'express';
import bodyParser from 'body-parser';
import mysql from 'mysql2/promise';
import { promisify } from 'util';
import fileUpload from 'express-fileupload';
import fs from 'fs';

const rmFile = promisify(fs.unlink);

import { hashPassword, isPasswordCorrect } from "./helpers";
import {
    generateTokens,
    generateAccessToken,
    jwtVerify,
    checkRefreshToken,
    invalidateToken,
    accessTokenLifetime, secretTokenKey
} from "./front/jwt";

const port = process.env.PORT || 8000;
const app = express();

const userTable = 'user';
const filesTable = 'files';
const uploadPath = '/tmp/';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    next();
});

app.use(fileUpload({}));

app.post('/signin', async (req, res) => {
    let { username, password } = req.body;
    let [rows] = await db.execute(`SELECT id, email, hash, salt FROM ${userTable} WHERE username = ?`, [username]);
    if (rows.length < 1) {
        return res.send({ ok: false, error: 'Wrong username' });
    }
    const { hash, salt, email, id } = rows[0];
    if (!await isPasswordCorrect(hash, salt, password)) {
        return res.send({ ok: false, error: 'Wrong password' });
    }

    let { accessToken, refreshToken } = generateTokens({ id, email });

    res.send({ ok: true, accessToken, refreshToken });
});

app.post('/signin/new_token', async (req, res) => {
    let { refreshToken } = req.body;
    try {
        let tokenData = await jwtVerify(refreshToken, secretTokenKey);
        checkRefreshToken(tokenData.deviceId);

        let accessToken = generateAccessToken(tokenData);
        res.send({ ok: true, accessToken });
    } catch (e) {
        res.send({ ok: false, error: e.message });
    }
});

async function authChecker(req, res, next) {
    let { authorization } = req.headers;
    if (!authorization || !authorization.startsWith('JWT')) {
        return res.send({ ok: false, error: 'Missing authorization token' });
    }
    let token = authorization.slice(4);
    try {
        req.accessToken = await jwtVerify(token, secretTokenKey);
        // checkRefreshToken(req.accessToken.deviceId);
        next();
    } catch (e) {
        return res.send({ ok: false, error: e.message });
    }
}

app.get('/info', authChecker, async (req, res) => {
    res.send({ ok: true, id: req.accessToken.id });
});

app.get('/logout', authChecker, async (req, res) => {
    let { deviceId } = req.accessToken;
    invalidateToken(deviceId, Date.now() + accessTokenLifetime);
    res.send({ ok: true });
});

app.post('/file/upload', authChecker, async (req, res) => {
    console.log('req.files', req.files);
    let { file } = req.files;
    let { size, mimetype, name } = file;
    let ext = name.split('.').slice(-1)[0];
    let { id } = req.accessToken;

    let [{ insertId }] = await db.execute(`INSERT INTO ${filesTable} (name, mimetype, ext, size, owner) VALUES ("${name}", "${mimetype}", "${ext}", ${size}, ${id})`);

    let mv = promisify(file.mv);
    await mv(uploadPath + insertId);

    res.send({ ok: true, id: insertId });
});

app.get('/file/list', authChecker, async (req, res) => {
    let { list_size: listSize = 10, page = 1 } = req.body;
    let { id } = req.accessToken;

    const [rows] = await db.execute(`SELECT * FROM ${filesTable} WHERE owner = ${id} LIMIT ${listSize} OFFSET ${(page-1) * listSize}`);

    res.send({ ok: true, files: rows });
});

app.delete('/file/delete/:id', authChecker, async (req, res) => {
    let { id: ownerId } = req.accessToken;
    let { id: fileId } = req.params;

    const [rows] = await db.execute(`DELETE FROM ${filesTable} WHERE owner = ${ownerId} AND id = ${fileId}`);
    if (rows.affectedRows === 0)
        return res.send({ ok: false, error: 'File not found' });

    try {
        await rmFile(uploadPath + fileId);
        res.send({ ok: true });
    } catch (e) {
        return res.send({ ok: false, error: e.message });
    }
});

app.get('/file/:id', authChecker, async (req, res) => {
    let { id: ownerId } = req.accessToken;
    let { id: fileId } = req.params;

    const [rows] = await db.execute(`SELECT * FROM ${filesTable} WHERE owner = ${ownerId} AND id = ${fileId}`);
    if (rows.length)
        res.send({ ok: true, file: rows[0] });
    else
        res.send({ ok: false, error: 'File not found' });
});

app.get('/file/download/:id', authChecker, async (req, res) => {
    let { id: ownerId } = req.accessToken;
    let { id: fileId } = req.params;

    const [rows] = await db.execute(`SELECT * FROM ${filesTable} WHERE owner = ${ownerId} AND id = ${fileId}`);
    if (rows.affectedRows === 0)
        return res.send({ ok: false, error: 'File not found' });

    let { name, mimetype } = rows[0];
    res.setHeader('Content-type', mimetype);
    res.download(uploadPath + name);
});

app.put('/file/update/:id', authChecker, async (req, res) => {
    let { id: ownerId } = req.accessToken;
    let { id: fileId } = req.params;

    let { file } = req.files;
    let { size, mimetype, name } = file;
    let ext = name.split('.').slice(-1)[0];

    let mv = promisify(file.mv);
    await mv(uploadPath + name);

    const [rows] = await db.execute(`UPDATE ${filesTable} SET name = "${name}", mimetype = "${mimetype}", ext = "${ext}", size = ${size} WHERE owner = ${ownerId} AND id = ${fileId}`);
    if (rows.affectedRows === 0)
        return res.send({ ok: false, error: 'File not found' });

    res.send({ ok: true });

});

app.post('/signup', async (req, res) => {
    let { username, email, password } = req.body;
    try {
        const { salt, hash } = await hashPassword(password);
        const [{ insertId: id }] = await db.execute(`INSERT INTO ${userTable} (username, email, hash, salt) VALUES ("${username}", "${email}", "${hash}", "${salt}")`);

        const { accessToken, refreshToken } = generateTokens({ id, email });

        res.send({ ok: true, accessToken, refreshToken });
    } catch (e) {
        console.log('err', e);
        switch (e.code) {
            case 'ER_DUP_ENTRY':
                return res.send({ ok: false, error: 'User already exist' });
            default:
                return res.send({ ok: false, error: e.message });
        }
    }
});

let db;
async function main() {
    db = await mysql.createConnection({host:'localhost', user: 'root', password: 'qwerty', database: 'test'});
}
main();

app.listen(port, () => console.log(`Server is listening on port: ${port}`));
