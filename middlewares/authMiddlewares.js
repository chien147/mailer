const asyncHandler = require("express-async-handler");
const User = require("../model/userModel");
const jwt = require("jsonwebtoken");

// vd về verify : trả về một 
// dùng để xác định token của người đùng
const verifya =asyncHandler(async (req, res, next)=>{
  try {
    
    const token = req.cookies.token;
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(verified.id).select("-password");
    res.status(200).json(user)
    next()
  } catch (error) {
    res.status(401);
    throw new Error("Not authorized, please login");
  }
})


const protect = asyncHandler(async (req, res, next) => {
  try {
    // lấy token ở cookies
    const token = req.cookies.token;
    if (!token) {
      res.status(401);
      throw new Error("Not authorized, please login");
    }

    // dùng để xác định token của người đùng
    //  trả về id 
    // iat (Issued at) : nhãn thời gian mà cái token được tạo
    // exp (Expiration time): xác định thời gian hết hạn của Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    // Get user id from token
    // findById tìm kiếm tài nguyên cụ thể bằng id 
    // select("-") : loại bỏ password 
    const user = await User.findById(verified.id).select("-password");

    if (!user) {
      res.status(404);
      throw new Error("User not found");
    }
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User suspended, please contact support");
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401);
    throw new Error("Not authorized, please login");
  }
});

const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized, account not verified");
  }
});

const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an author");
  }
});

const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an admin");
  }
});

module.exports = {
  protect,
  verifiedOnly,
  authorOnly,
  adminOnly,
  verifya
};