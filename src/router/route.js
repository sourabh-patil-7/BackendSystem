const express = require("express");
const router = express.Router();
const {
  registerUser,
  getUser,
  login,
  updateUser,
  refreshToken,
  logout,
  generateOtp,
  verifyOtp,
  resetPassword,
} = require("../controllers/authController");
const { authenticate, localVariable } = require("../middleware/authMiddleware");



// POST
router.post("/register", registerUser);
router.post("/login", login);
router.post("/logout", logout);
router.post("/verifyotp", verifyOtp);


// GET
router.get("/user/:username", authenticate, getUser);
router.get("/generateotp", localVariable, generateOtp);
router.get("/refresh", refreshToken);


// Testing
router.get("/test", (req, res) => {
  res.send({ message: "its working" });
});


// PUT
router.put("/updateuser", authenticate, updateUser);
router.put("/resetpassword", resetPassword);


// DELETE
// router.delete("/deleteuser");
module.exports = router;
