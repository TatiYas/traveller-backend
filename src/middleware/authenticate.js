import createHttpError from 'http-errors'; /* поки відсутні дані */
import { SessionsCollection } from '../database/models/session.js';/* поки відсутні дані */
import { UsersCollection } from '../database/models/user.js';/* поки відсутні дані */

export const authenticate = async (req, res, next) => {
  if (!req.cookies.accessToken) {
    next(createHttpError(401, 'Please provide access token in cookies'));
    return;
  }

  const session = await SessionsCollection.findOne({
    accessToken: req.cookies.accessToken,
  });

  if (!session) {
    next(createHttpError(401, 'Session not found'));
    return;
  }

  const isAccessTokenExpired =
    new Date() > new Date(session.accessTokenValidUntil);

  if (isAccessTokenExpired) {
    return next(createHttpError(401, 'Access token expired'));
  }

  const user = await UsersCollection.findById(session.userId);

  if (!user) {
    next(createHttpError(401));
    return;
  }

  req.user = user;

  next();
};