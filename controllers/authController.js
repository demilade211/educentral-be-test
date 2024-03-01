import UserModel from "../models/user"   
import jwt from 'jsonwebtoken';
import bcrypt from "bcryptjs";
import crypto from "crypto"
import sendEmail from "../utils/sendEmail" 
import { handleEmail } from "../utils/helpers"; 
  
 

export const registerUser = async (req, res, next) => {

    try {
        const {email, password, confirmPassword } = req.body

        if (!email || !password || !confirmPassword) return res.send("All fields required")

        if (password !== confirmPassword) return res.send("Passwords do not match")

        if (password.length < 6) return res.send("Password cannot be less than 6 characters")

        const user = await UserModel.findOne({ email: email.toLowerCase() })

        if (user) return res.send("User already registered") 

        //const dob = new Date(dateOfBirth)


        const savedUser = await UserModel.create({
            email: email.toLowerCase(), 
            password, 
        });



        const payload = { userid: savedUser._id }
        const authToken = await jwt.sign(payload, process.env.SECRETE, { expiresIn: '7d' })//expiresIn: '7d' before

        return res.redirect('/dashboard.html');

    } catch (error) {
        return res.status(500).send("Internal Server Error");
    }
}

//To login {{DOMAIN}}/api/login
export const loginUser = async (req, res, next) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.send("All fields required");
        }

        if (password.length < 6) {
            return res.send("Password cannot be less than 6 characters");
        }

        const user = await UserModel.findOne({ email: email.toLowerCase() }).select("+password");

        if (!user) {
            return res.send("Invalid Credentials");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.send("Invalid Credentials");
        }

        const payload = {
            userid: user._id
        };

        const authToken = await jwt.sign(payload, process.env.SECRET, { expiresIn: '7d' });

        let name = user.name || "No name";

        // Send response with redirect
        return res.redirect('/dashboard.html');
    } catch (error) { 
        return res.status(500).send("Internal Server Error");
    }
};

//Forgot password {{DOMAIN}}/api/v1/password/forgot
export const forgotPassword = async(req,res,next)=>{

    const {email} = req.body;

    try {

        const user = await UserModel.findOne({email:email.toLowerCase()})

        if(!user) return res.send("User with this email not found",404) 

        // Generate token
        const resetToken = crypto.randomBytes(20).toString('hex');

        // Hash and set to resetPasswordToken
        user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        // Set token expire time
        user.resetPasswordExpire = Date.now() + 30 * 60 * 1000

        await user.save({validateBeforeSave: false});

        //create password reset url
        const resetUrl = `/reset.html?token=${resetToken}`;

        const message = `Your password reset token is as follows:\n\n${resetUrl}\n\nif you have not 
        requested this email, then ignore it.`

        try {
            await sendEmail({
                email: user.email,
                subject: "Password Recovery",
                message
            })

            return res.status(200).json({
                success: true,
                message: `Email sent to ${user.email}`
            })
        } catch (error) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;

            await user.save({validateBeforeSave: false})
            return res.send(error.message) 

        }


    } catch (error) {
        return res.status(500).send("Internal Server Error");
    }
}

//reset password {{DOMAIN}}/api/v1/password/reset/:token
export const resetPassword = async(req,res,next)=>{
    const {token} = req.params;
    const {password,confirmPassword} = req.body;

    try {
        // Hash URL token
    const resetPasswordToken = crypto.createHash('sha256').update(token).digest('hex')

    const user = await UserModel.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    })

    if(!user)  return res.send('Password reset token is invalid or has been expired') 

    if (password !== confirmPassword) {
        res.send('Password does not match') 
    }
 

    user.password = password;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save({ validateBeforeSave: false });

    const payload = {userid: user._id}
    const authToken = await jwt.sign(payload,process.env.SECRETE,{expiresIn: '7d'})

    return res.send("Password changed successfully")
        
    } catch (error) {
        return res.status(500).send("Internal Server Error");
    }
} 

