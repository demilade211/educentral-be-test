import  express from "express"; 
import { registerUser,loginUser,forgotPassword,resetPassword } from "../controllers/authController";

const router = express.Router()

router.route('/register').post(registerUser);
router.route('/login').post(loginUser);
 

router.route('/password/forgot').post(forgotPassword); 
 

router.route('/password/reset/:token').get(resetPassword);



export default router;