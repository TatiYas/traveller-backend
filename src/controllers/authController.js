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


const BCRYPT_ROUNDS = 12;

export const registerUser = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    // Базова валідація (можна замінити)
    if (!name || !email || !password || password.length < 8) {
      throw createHttpError(400, 'Некоректні дані для реєстрації');
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw createHttpError(409, 'Цей email вже використовується');
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const newSession = await createSession(newUser._id);

    setSessionCookies(res, newSession); // має встановлювати httpOnly, secure, sameSite: 'strict' тощо

    res.status(201).json({
      message: 'Користувача успішно зареєстровано',
      user: { id: newUser._id, name: newUser.name, email: newUser.email },
    });
  } catch (err) {
    next(err);
  }
};

export const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      throw createHttpError(401, 'Невірні облікові дані');
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw createHttpError(401, 'Невірні облікові дані');
    }

    // Видаляємо всі попередні сесії (захист від множинних логінів)
    await Session.deleteMany({ userId: user._id });

    const newSession = await createSession(user._id);

    setSessionCookies(res, newSession);

    res.status(200).json({
      message: 'Успішний вхід',
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    next(err);
  }
};

export const refreshUserSession = async (req, res, next) => {
  try {
    const { sessionId, refreshToken } = req.cookies;

    if (!sessionId || !refreshToken) {
      throw createHttpError(401, 'Відсутні токени для оновлення сесії');
    }

    const session = await Session.findOne({ _id: sessionId, refreshToken });
    if (!session) {
      throw createHttpError(401, 'Сесію не знайдено / токен невалідний');
    }

    if (new Date() > new Date(session.refreshTokenValidUntil)) {
      await Session.deleteOne({ _id: sessionId });
      throw createHttpError(401, 'Refresh-токен прострочено');
    }

    // РОТАЦІЯ refresh-токена — ключова безпека 2025–2026
    const newSession = await createSession(session.userId);

    // Видаляємо стару сесію
    await Session.deleteOne({ _id: sessionId });

    setSessionCookies(res, newSession);

    res.status(200).json({
      message: 'Сесію успішно оновлено',
    });
  } catch (err) {
    next(err);
  }
};

export const logoutUser = async (req, res, next) => {
  try {
    const { sessionId } = req.cookies;

    if (sessionId) {
      await Session.deleteOne({ _id: sessionId });
    }

    // Очищаємо всі можливі cookies
    res.clearCookie('sessionId');
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.status(204).send();
  } catch (err) {
    next(err);
  }
};

export const requestResetEmail = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      throw createHttpError(400, 'Email обов’язковий');
    }

    const user = await User.findOne({ email });

    // Завжди повертає 200, навіть якщо користувача немає 
    if (!user) {
      return res.status(200).json({
        message: 'Лист для скидання пароля надіслано (якщо email існує)',
      });
    }

    const resetToken = jwt.sign(
      { sub: user._id, email: user.email },
      // eslint-disable-next-line no-undef
      process.env.JWT_SECRET,
      { expiresIn: '15m' },
    );

    const templatePath = path.resolve('src/templates/reset-password-email.html');
    const templateSource = await fs.readFile(templatePath, 'utf-8');
    const template = handlebars.compile(templateSource);

    const html = template({
      name: user.name || user.username || 'Користувач',
      // eslint-disable-next-line no-undef
      link: `${process.env.FRONTEND_DOMAIN}/reset-password?token=${resetToken}`,
    });

    await sendEmail({
      // eslint-disable-next-line no-undef
      from: process.env.SMTP_FROM,
      to: email,
      subject: 'Скидання пароля',
      html,
    });

    res.status(200).json({
      message: 'Лист для скидання пароля надіслано',
    });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { token, password } = req.body;

    if (!token || !password || password.length < 8) {
      throw createHttpError(400, 'Некоректні дані для скидання пароля');
    }

    let payload;
    try {
      // eslint-disable-next-line no-undef
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      throw createHttpError(401, 'Невалідний/прострочений токен');
    }

    const user = await User.findOne({ _id: payload.sub, email: payload.email });
    if (!user) {
      throw createHttpError(404, 'Користувача не знайдено');
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await User.updateOne({ _id: user._id }, { password: hashedPassword });

    // Force logout з усіх пристроїв
    await Session.deleteMany({ userId: user._id });

    res.clearCookie('sessionId');
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.status(200).json({
      message: 'Пароль успішно змінено',
    });
  } catch (err) {
    next(err);
  }
};