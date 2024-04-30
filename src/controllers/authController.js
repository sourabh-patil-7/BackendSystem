const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const UserModel = require("../models/userModel");

const otpGenerator = require("otp-generator");
const OtpModel = require("../models/passwordOtpModel");
const CustomError = require("../utils/customError");
const {
  createToken,
  createRefreshToken,
  convertToMilliseconds,
} = require("../utils/helpers");
const { sendEmail, emailBodyGenerate } = require("../utils/email");
const { REFRESH_TOKEN_EXPIRE_TIME } = require("../config");

// bcrypt salt rounds
const saltRounds = 10;

// Production or development status
const status = process.env.STATUS || "development";

// REGISTER USER
async function registerUser(req, res) {
  const { username, email, password } = req.body;

  try {
    if (!username)
      return res.status(400).send({ error: "Username is required" });
    if (!email) return res.status(400).send({ error: "Email is required" });
    if (!password)
      return res.status(400).send({ error: "Password is required" });

    if (!validator.isEmail(email))
      return res.status(400).send({ error: "Email is not valid" });

    if (!validator.isStrongPassword(password))
      return res.status(400).send({ error: "Password must be strong" });

    // check username and email already exits
    const usernameExits = await UserModel.exists({ username });
    const emailExits = await UserModel.exists({ email });
    if (emailExits || usernameExits) {
      let errors = [];

      if (usernameExits) errors.push("Username unavaliable");
      if (emailExits) errors.push("Email already in use");

      return res.status(400).send({ errors });
    }

    // Hash password and Store in db
    bcrypt.hash(password, saltRounds, function (err, hash) {
      if (err)
        return res.status(500).send({ error: "Unable to hash the password" });
      // create user model with hashed password
      const user = new UserModel({
        username,
        email,
        password: hash,
      });

      // save user to db
      user
        .save()
        .then((user) => {
          // generate token

          const token = createToken({
            userId: user._id,
            username: user.username,
          });

          // Generate Refresh Token
          const refreshToken = createRefreshToken({
            userId: user._id,
            username: user.username,
          });

          const options = {
            httpOnly: true, // only accessible by web server
            secure: false, // https
            sameSite: "lax", //cross-site cookie
            maxAge: convertToMilliseconds(REFRESH_TOKEN_EXPIRE_TIME), // expiry time
          };

          if (status === "production") {
            options.secure = true;
          }

          res.cookie("refresh", refreshToken, options);

          res.status(201).send({ username: user.username, token });
        })
        .catch((err) => res.status(500).send(err));
    });
  } catch (error) {
    return res.status(500).send(error);
  }
}


// LOGIN
async function login(req, res) {
  const { username, password } = req.body;

  try {
    if (!username) return res.send({ error: "Username is required" });
    if (!password) return res.send({ error: "Password is required" });

    const user = await UserModel.findOne({ username });

    if (!user) return res.status(404).send({ error: "Username not found" });

    bcrypt.compare(password, user.password, async function (err, result) {
      if (err) return res.status(500).send({ error: "Internal Server Error" });

      if (!result)
        return res.status(400).send({ error: "Username or Password Wrong" });

      const token = createToken({
        userId: user._id,
        username: user.username,
      });

      const refreshToken = createRefreshToken({
        userId: user._id,
        username: user.username,
      });

      const options = {
        httpOnly: true, // only accessible by web server
        secure: false, // https
        sameSite: "lax", //cross-site cookie
        maxAge: convertToMilliseconds(REFRESH_TOKEN_EXPIRE_TIME), // expiry time
      };

      if (status === "production") {
        options.secure = true;
      }

      res.cookie("refresh", refreshToken, options);

      // Save last login time

      await UserModel.findOneAndUpdate(
        { username },
        { last_login: Date.now() }
      );

      return res.status(200).send({
        username: user.username,
        token,
      });
    });
  } catch (error) {
    return res.status(500).send(error);
  }
}


// GET USER
async function getUser(req, res) {
  const { username } = req.params;
  if (username != req.user.username)
    return res.status(400).send({ error: "Auth Failed" });

  if (!username) return res.send(400).send({ error: "Username is required" });

  const user = await UserModel.findOne({ username });

  if (!user) return res.status(500).send({ error: "User not found" });

  const { password, ...rest } = user.toJSON();
  res.send(rest);
}


// UPDATE USER
async function updateUser(req, res) {
  const { userId } = req.user;
  try {
    if (!userId) throw new Error("User not found");

    const body = req.body;

    // check if body is empty
    if (Object.keys(body).length === 0)
      throw new Error("Update body cannot be empty");

    // update the user
    const updateUser = await UserModel.findOneAndUpdate({ _id: userId }, body);

    if (!updateUser) throw new Error("User Update Failed");

    res.status(201).send({ msg: "User updated successfully" });
  } catch (error) {
    return res.status(400).send({ error: error.message });
  }
}


// REFRESH TOKEN
async function refreshToken(req, res, next) {
  // const { refreshToken } = req.body;
  const cookies = req.cookies;

  try {
    if (!cookies?.refresh) throw new Error("Token not found");
    const refreshToken = cookies.refresh;
    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
      async function (err, decoded) {
        try {
          if (err) throw new CustomError("Session Expired", 401);

          const foundUser = await UserModel.findOne({
            username: decoded.username,
          });

          if (!foundUser) throw new Error("Unauthorized");

          const token = createToken({
            userId: foundUser._id,
            username: foundUser.username,
          });

          res.status(200).send({ token });
        } catch (error) {
          next(error);
        }
      }
    );
  } catch (error) {
    next(error);
    return res.status(400).send({ error: error.message });
  }
}


// GENERATE OTP
async function generateOtp(req, res, next) {
  try {
    const { username } = req?.query;
    if (!username) throw new Error("Username is required");

    const user = await UserModel.findOne({ username });
    if (!user) throw new CustomError("User not found", 400);

    const otp = otpGenerator.generate(6, {
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    bcrypt.hash(otp, 10, async function (err, hash) {
      try {
        if (err) throw new Error("Failed generate otp");

        // delete exiting otps in database for this user

        const otpdb = await OtpModel.findOne({ username });

        if (!otpdb) {
          const newOtp = new OtpModel({
            username: user.username,
            otp: hash,
            expiredAt: Date.now() + 60 * 60 * 1000,
          });
          await newOtp.save();
        }

        await OtpModel.findOneAndUpdate(
          { username },
          {
            otp: hash,
            expiredAt: Date.now() + 60 * 60 * 1000,
          }
        );

        const emailBody = emailBodyGenerate({
          username: user.username,
          otp,
        });

        await sendEmail(
          { email: user.email, subject: "Authentication System Password Reset" },
          emailBody
        );

        req.app.locals.username = username;

        res.send({ msg: "Otp Sent to Your Email" });
      } catch (err) {
        next(err);
      }
    });
  } catch (error) {
    next(error);
  }
}


// OTP VERICATTION
async function verifyOtp(req, res, next) {
  try {
    const { otp } = req.body;
    const { username } = req?.app?.locals;

    if (!username) throw new CustomError("Authentication Failed", 500);
    if (!otp) throw new CustomError("Otp is required", 400);

    const hashedotp = await OtpModel.findOne({ username });

    if (!hashedotp && !hashedotp.otp) throw new CustomError("OTP is not valid");

    if (hashedotp.expiredAt < Date.now())
      throw new CustomError("OTP is expired");

    bcrypt.compare(otp, hashedotp.otp, async function (err, result) {
      try {
        if (err) throw new Error("OTP Verification Faield", 500);

        if (!result) throw new Error("OTP is not valid", 400);
        req.app.locals.resetSession = true;

        await OtpModel.findOneAndUpdate(
          { username },
          {
            otp: null,
            expiredAt: null,
          }
        );

        res.send({ msg: "OTP Verified Successfully" });
      } catch (error) {
        next(error);
      }
    });
  } catch (error) {
    next(error);
  }
}

// RESET PASSWORD
async function resetPassword(req, res, next) {
  try {
    const { resetSession, username } = req.app.locals;
    if (!resetSession) throw new Error("Authentication Failed");
    if (!username) throw new Error("Authentication Failed");

    const { password, confirmpassword } = req.body;
    if (!password || !confirmpassword)
      throw new CustomError("All fields are required", 400);

    const user = UserModel.findOne({ username });
    if (!user) throw new CustomError("User not found", 400);

    if (password !== confirmpassword)
      throw new CustomError("Password does not match");

    if (!validator.isStrongPassword(password))
      throw new CustomError("Password is not strong");

    req.app.locals.resetSession = false;
    req.app.locals.username = null;

    bcrypt.hash(password, saltRounds, async function (err, hash) {
      if (err) throw new CustomError("Internal Server Error", 500);
      const updated = await UserModel.findOneAndUpdate(
        { username },
        { password: hash }
      );
      if (!updated) throw new Error("Password Reset Failed", 500);

      res.send({ msg: "Password reset successfully" });
    });
  } catch (error) {
    next(error);
  }
}

// LOGOUT
async function logout(req, res) {
  const { refresh } = req.cookies;

  if (!refresh) return res.sendStatus(204);
  await res.clearCookie("refresh", {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
  });

  res.json({ message: "Cookie Cleared" });
}

module.exports = {
  registerUser,
  login,
  getUser,
  updateUser,
  refreshToken,
  generateOtp,
  verifyOtp,
  resetPassword,
  logout,
};
