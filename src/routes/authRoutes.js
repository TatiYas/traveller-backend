import { Router } from 'express';
import { loginUserSchema, registerUserSchema } from '../validations/authValidation.js';
import { celebrate } from 'celebrate';
import { registerUser, loginUser, resetPassword} from '../controllers/authController.js';
import { resetPasswordSchema } from '../validations/authValidation.js';


const router = Router();


router.post("/auth/register", celebrate(registerUserSchema), registerUser);
router.post("/auth/login", celebrate(loginUserSchema), loginUser);
//...

router.post("/auth/reset-password",celebrate(resetPasswordSchema),resetPassword,                      
);

export default router;