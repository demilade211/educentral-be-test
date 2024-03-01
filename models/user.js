import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";

const Schema = mongoose.Schema;

const UserSchema = new Schema({ 
    email: {
        type: String,
        required: [true, 'Please enter your email'],
        unique: true,
        validate: [validator.isEmail, 'Please enter valid email address']
    },
    password: {
        type: String,
        required: [true, 'Please enter your password'],
        minlength: [6, 'Your password must be longer than 6 characters'],
        select: false
    }, 
    role: {
        type: String,
        default: 'user',
        enum: ['user', 'seller', 'admin']
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date
},
    { timestamps: true });

// Encrypting password before saving user
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next()
    }

    this.password = await bcrypt.hash(this.password, 10)
})

export default mongoose.model("User", UserSchema);