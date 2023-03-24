const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../model/userModel');
const { generateToken, hashToken } = require('../utils');
var parser = require('ua-parser-js')
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const Token = require('../model/tokenModel');
const crypto = require("crypto")
const Cryptr = require("cryptr")
const cryptr = new Cryptr(process.env.CRYPTR_KEY)

//  đăng ký tài khoản
const registerUser = asyncHandler(async (req, res) => {
    // láy dữ liệu từ form đăng ký 
    const { name, email, password } = req.body;
    try {
        // kiểm tra xem đã điền đủ thông tin không
        if (!name || !password || !email) {
            res.status(400)
            throw new Error("flease fill in all the required fiedls")
            // throw new Error("xin vui lòng điền đầy đủ vào những ô trống cần thiết")
        }
        // kiểm tra xem password có độ dài lớn hơn 6 ko
        else if (password.length < 6) {
            res.status(400)
            throw new Error('flease password length > 6')
        }

        // kiểm tra xem người dùng có tồn tại không
        const userExists = await User.findOne({ email })
        if (userExists) {
            res.status(400)
            throw new Error("email already in use")
        }

        const ua = parser(req.headers['user-agent'])
        const userAgent = [ua.ua]

        // tạo người dùng mới
        const user = await User.create({
            name,
            email,
            password,
            userAgent,
        })

        // Generate Token
        //const token = generateToken(user._id);

        // Send HTTP-only cookie
        // res.cookie("token", token, {
        //     path: "/",
        //     httpOnly: true,
        //     expires: new Date(Date.now() + 1000 * 86400),
        //     sameSite: "none",
        //     secure: true
        // })

        if (user) {
            const { _id, name, email, phone, bio, photo, role, isVerified } = user
            res.status(201).json({
                _id, name, email, phone, bio, photo, role, isVerified
                //_id, name, email, phone, bio, photo, role, isVerified, token
            })
        }
    } catch (error) { 
        res.status(400).send("Invalid user data");
    }

})

// đăng nhập tài khoản
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    //   Validation
    if (!email || !password) {
        res.status(400);
        throw new Error("Please add email and password");
    }

    const user = await User.findOne({ email });
    if (!user) {
        res.status(404);
        throw new Error("User not found, please signup");
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        res.status(400);
        throw new Error("Invalid email or password");
    }

    // Trgger 2FA for unknow UserAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    console.log(thisUserAgent);

    const allowedAgent = user.userAgent.includes(thisUserAgent);
    if (!allowedAgent) {
        // Genrate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000);
        console.log(loginCode);

        // Encrypt login code before saving to DB
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

        // Delete Token if it exists in DB
        let userToken = await Token.findOne({ userId: user._id });
        if (userToken) {
            await userToken.deleteOne();
        }

        // Save Tokrn to DB
        await new Token({
            userId: user._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
        }).save();

        res.status(400);
        throw new Error("new browser or device detected");
    }


    // Generate Token
    const token = generateToken(user._id);

    if (user && passwordIsCorrect) {
        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secure: true,
        });

        const { _id, name, email, phone, bio, photo, role, isVerified } = user;
        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
            token,
        });
    } else {
        res.status(500);
        throw new Error("Something went wrong, please try again");
    }
});

// Send Login Code khi đăng nhập bằng máy khác yêu cầu cần phải nhập mã ở gmail
const sendLoginCode = asyncHandler(async (req, res) => {
    // lấy dư liệu từ link
    const { email } = req.params;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    // Find Login Code in DB
    let userToken = await Token.findOne({
        userId: user._id,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired token, please login again");
    }

    const loginCode = userToken.lToken;
    const decryptedLoginCode = cryptr.decrypt(loginCode);

    // Send Login Code
    const subject = "Login Access Code";
    const send_to = email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "chieens147@gmail.com";
    const template = "loginCode";
    const name = user.name;
    const link = decryptedLoginCode;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: `Access code sent to ${email}` });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }

})


const logoutUser = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true
    })
    return res.status(200).json({ message: "dang xuat thanh cong" })
})

const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
        });
    } else {
        res.status(404);
        throw new Error("User not found");
    }
});

// update user
const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)
    if (user) {
        const { name, email, phone, bio, photo, role, isVerified } = user;
        user.email = email
        user.name = req.body.name || name
        user.phone = req.body.phone || phone
        user.bio = req.body.bio || bio
        user.photo = req.body.photo || photo
        const updateUser = await user.save()
        res.status(200).json({
            _id: updateUser._id,
            name: updateUser.name,
            email: updateUser.email,
            phone: updateUser.phone,
            bio: updateUser.bio,
            photo: updateUser.photo,
            role: updateUser.role,
            isVerified: updateUser.isVerified,

        })
    }
    else {
        res.status(404);
        throw new Error("User not found");
    }
})


// delete user
const deleteUser = asyncHandler(async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id, req.params);
        res.status(201).json({
            message: "User deleted successfully",
            success: true,
        });
        // const user = User.findById(req.params.id);
        // if (!user) {
        //     res.status(404);
        //     throw new Error("User not found");
        // }
        // await user.remove();
        // res.status(200).json({
        //     message: "User deleted successfully",
        // });
    } catch (error) {
        res.status(400).json({ message: error.message, success: false })
    }
})

// get users
const getUsers = asyncHandler(async (req, res) => {
    const users = await User.find().sort("-createdAt").select("-password")
    if (!users) {
        res.status(500)
        throw new Error("something went wrong")
    }
    res.status(200).json(users)
})

const getstatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }
    const verify = jwt.verify(token, process.env.JWT_SECRET)
    if (verify) {
        return res.json(true);
    }
    return res.json(false)
})

const upgradeUser = asyncHandler(async (req, res) => {
    const { role, id } = req.body;
    const user = await User.findById(id)
    if (!user) {
        res.status(400);
        throw new Error("user not found")
    }
    user.role = role;
    await user.save();
    res.status(200).json({
        message: `user role updated to ${role}`
    })
})

// send automated email
const sendAutomatedEmail = asyncHandler(async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;
    if (!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error("missing email parameter ")
    }
    const user = await User.findOne({ email: send_to })

    if (!user) {
        res.status(404);
        throw new Error("user not found")
    }
    const sent_from = process.env.EMAIL_USER
    const name = user.name
    const link = `${process.env.FRONEND_URL}${url}`

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
        res.status(200).json({
            message: link
        })
    } catch (error) {
        res.status(500);
        throw new Error("email not sent, please try again")
    }

})


const sendVerifycationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)
    if (!user) {
        res.status(400)
        throw new Error("user not found ")
    }
    if (user.isVerified) {
        res.status(400)
        throw new Error("user already verified")
    }
    let token = await Token.findOne({ userId: user._id })

    if (token) {
        await token.deleteOne()
    }

    // create verification token and save
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id
    console.log(verificationToken);
    // res.send("token")

    // hash token and save
    const hashedToken = hashToken(verificationToken)

    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000)
    }).save()

    const verificationUrl = `${process.env.FRONEND_URL}/verify/${verificationToken}`

    const subject = "verify your account - auth"
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER
    const reply_to = "chieens147@gmail.com"
    const template = "verifyEmail"
    const name = user.name
    const link = verificationUrl
    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Verification Email Sent" });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }

})

// verifyUser
const verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params
    const hashedToken = hashToken(verificationToken)
    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: { $gt: Date.now() }
    })
    if (!userToken) {
        res.status(400)
        throw new Error("invalid or expired token")
    }

    const user = await User.findOne({ _id: userToken.userId })

    if (user.isVerified) {
        res.status(400);
        throw new Error("User is already verified")
    }

    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: "account verification successful" })
})

// forgot password
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email })
    if (!user) {
        res.status(404)
        throw new Error("No user with this email")
    }
    // delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne()
    }
    // create verification token and save
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id

    console.log(resetToken);

    // hash token and save
    const hashedToken = hashToken(resetToken)

    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save();
    // construct verification URL
    const resetUrl = `${process.env.FRONEND_URL}/resetpassword/${resetToken}`

    const subject = "Password Reset Request - AUTH:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "chieens147@gmail.com";
    const template = "forgotPassword";
    const name = user.name;
    const link = resetUrl;
    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Password Reset Email Sent" });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }
})

// reset password
const resetpassword = asyncHandler(async (req, res) => {
    const { resetToken } = req.params;
    const { password } = req.body
    const hashedToken = hashToken(resetToken)
    const userToken = await Token.findOne({
        rToken: hashedToken,
        expiresAt: { $gt: Date.now() }
    })
    if (!userToken) {
        res.status(404)
        throw new Error("invalid or expired token")
    }
    const user = await User.findOne({ _id: userToken.userId })
    user.password = password;
    await user.save()
    res.status(200).json({ message: "password reset successful, please login " })

})

// change password
const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, password } = req.body;
    const user = await User.findById(req.user._id)
    if (!user) {
        res.status(404)
        throw new Error("user not found")
    }
    if (!password || !oldPassword) {
        res.status(400)
        throw new Error("please enter old and new password")
    }

    // check if old password is correct
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

    // save new password 
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save()
        res.status(200).json({ message: "password change successful. please re-login" })
    } else {
        res.status(400);
        throw new Error("old password is inconnect")
    }


})

const loginWithCode = asyncHandler(async (req, res)=>{
    const {email} = req.params;
    const {loginCode} = req.body
    const user = await User.findOne({email})
    if (!user) {
        res.status(404)
        throw new Error("user not found")
    }

    const userToken =await Token.findOne({
        userId: user._id,
        expiresAt: {$gt: Date.now(),}
    })
    if (!userToken) {
        res.status(404)
        throw new Error("invalid or expired token, please login again")
    }
    const decryptedLoginCode = cryptr.decrypt(userToken.lToken)
    if (loginCode!==decryptedLoginCode) {
        res.status(404)
        throw new Error("incorrect loggin code, please try again")
    }else{
        const ua = parser(req.headers["user-agent"])
        const thisUserAgent = ua.ua;
        user.userAgent.push(thisUserAgent)
        await user.save()

        const token = generateToken(user._id)
        res.cookie("token", token,{
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now()+1000*86400),
            sameSite: "none",
            secure: true,
        })
        const {_id, name, email, phone, bio, photo, role, inVerified} = user
        res.status(201).json({
            _id, name, email, phone, bio, photo, role, inVerified, token
        })
        userToken.lToken ="";
        await userToken.save()
    }
})


module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    updateUser,
    deleteUser,
    getUsers,
    getstatus,
    upgradeUser,
    sendAutomatedEmail,
    sendVerifycationEmail,
    verifyUser,
    forgotPassword,
    resetpassword,
    changePassword,
    sendLoginCode,
    loginWithCode
}