import { pbkdf2 as pbkdf2_, randomBytes } from 'crypto';
import { promisify } from 'util';

const pbkdf2 = promisify(pbkdf2_);

export async function hashPassword(password) {
    var salt = randomBytes(128).toString('base64');
    var hash = (await pbkdf2(password, salt, 100000, 64, 'sha512')).toString('hex');

    return {
        salt: salt,
        hash: hash,
    };
}

export async function isPasswordCorrect(savedHash, savedSalt, passwordAttempt) {
    return savedHash === (await pbkdf2(passwordAttempt, savedSalt, 100000, 64, 'sha512')).toString('hex');
}