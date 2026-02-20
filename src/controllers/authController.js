import bcrypt from 'bcrypt';
import createHttpError from 'http-errors';
import { User } from '../models/user.js';
import { Session } from '../models/session.js';
import { createSession, setSessionCookies } from '../services/auth.js';
import jwt from 'jsonwebtoken';
import { sendEmail } from '../utils/sendMail.js';
import handlebars from 'handlebars';
import path from 'node:path';
import fs from 'node:fs/promises';


//...

export const resetPassword = async (req, res, next) => {
  try {
    const { token, password } = req.body;

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtErr) {
      if (jwtErr.name === 'TokenExpiredError') {
        throw createHttpError(401, 'Термін дії токену сплив');
      }
      throw createHttpError(401, 'Токен недійсний');
    }

    if (payload.type !== 'password-reset') {
      throw createHttpError(400, 'Невірний тип токену');
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      throw createHttpError(404, 'Користувача не знайдено');
    }

    user.password = password;// pre-save → bcrypt.hash
    await user.save();

    await Session.deleteMany({ userId: user._id });

    const cookieOpts = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    };

    res
      .clearCookie('sessionId', cookieOpts)
      .clearCookie('accessToken', cookieOpts)
      .clearCookie('refreshToken', cookieOpts);

    return res.status(200).json({
      message: 'Пароль скинуто',
    });
  } catch (err) {
    next(err);
  }
};
export default router;