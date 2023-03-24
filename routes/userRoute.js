const express = require('express')
const { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getUsers, getstatus, upgradeUser, sendAutomatedEmail, sendVerifycationEmail, verifyUser, forgotPassword, resetpassword, changePassword, sendLoginCode, loginWithCode } = require('../controller/userController')
const { protect, adminOnly, verifya, authorOnly } = require('../middlewares/authMiddlewares')
const router = express.Router()

// jwt 
router.get('/verify', verifya)

// user
router.post('/register', registerUser)
router.post('/login', loginUser)
router.get('/logout', logoutUser)
router.get('/getUser', protect, getUser)
router.patch('/updateUser', protect, updateUser)
router.delete("/:id", protect, adminOnly, deleteUser);
router.get("/getUsers", protect, authorOnly, getUsers);
router.get("/getstatus", getstatus);
router.post("/upgradeUser", protect, adminOnly, upgradeUser);
router.post("/sendAutomatedEmail", protect, sendAutomatedEmail);
router.post("/sendVerifycationEmail", protect, sendVerifycationEmail);
router.patch("/verifyUser/:verificationToken", protect, verifyUser);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetpassword/:resetToken", resetpassword);
router.patch("/changePassword", protect, changePassword);

// sendLoginCode
router.post("/sendLoginCode/:email", sendLoginCode);


router.post("/loginWithCode/:email", loginWithCode);


module.exports = router
