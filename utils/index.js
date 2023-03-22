const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const generateToken = (id) => {
  // expiresIn trong jwt là tham số để xác định thời gian tính từ khi token được tạo ra đến khi nó hết hạn. Sau khi hết hạn, token sẽ 
  // không còn hợp lệ và người dùng sẽ cần phải yêu cầu một token mới để tiếp tục sử dụng dịch vụ.
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Hash Token
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token.toString()).digest("hex");
};

module.exports = {
  generateToken,
  hashToken,
};