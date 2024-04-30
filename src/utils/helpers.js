const jwt = require("jsonwebtoken");
const {
  REFRESH_TOKEN_EXPIRE_TIME,
  ACCESS_TOKEN_EXPIRE_TIME,
} = require("../config");


function createToken(data) {
  const token = jwt.sign(data, process.env.JWT_ACCESS_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRE_TIME,
  });
  return token;
}

function createRefreshToken(data) {
  const token = jwt.sign(data, process.env.JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRE_TIME,
  });
  return token;
}

// convert to miliseconds 1s, 4m, 5d , 12m
function convertToMilliseconds(timeComponent) {
  const conversions = {
    s: 1000,
    m: 1000 * 60,
    h: 1000 * 60 * 60,
    d: 1000 * 60 * 60 * 24,
  };

  const value = parseInt(timeComponent);

  const type = timeComponent.charAt(timeComponent.length - 1);

  if (!isNaN(value) && conversions[type]) {
    return value * conversions[type];
  } else {
    console.error("Invalid Input : ", timeComponent);
    return 0;
  }
}

module.exports = { createToken, createRefreshToken, convertToMilliseconds };
