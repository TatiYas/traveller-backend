import { Joi, Segments } from "celebrate";

export const registerUserSchema = {
  [Segments.BODY]: Joi.object({
    name: Joi.string().max(32).required(),
    email: Joi.string().email().max(64).required(),
    password: Joi.string().min(8).max(128).required(),
  }),
};

export const loginUserSchema = {
  [Segments.BODY]: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
};
import { Segments, Joi } from 'celebrate';

export const requestResetSchema = {
  [Segments.BODY]: Joi.object({
    email: Joi.string().email().required(),
  }),
};

export const resetPasswordSchema = {
  [Segments.BODY]: Joi.object({
    token: Joi.string().length(64).required(),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/[A-Z]/)
      .pattern(/[a-z]/)
      .pattern(/[0-9]/)
      .required(),
  }),
};