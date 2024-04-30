const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  username: {
    type: String,
    ref: "User",
    required: true,
  },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiredAt: { type: Date }, // Set an expiration time for the OTP
});

const OtpModel = mongoose.model("Otp", otpSchema);

module.exports = OtpModel;
