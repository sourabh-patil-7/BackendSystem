const jwt = require("jsonwebtoken");

function authenticate(req, res, next) {
  
  const token = req.headers?.authorization?.split(" ")[1];

  if (!token) return res.status(401).send({ error: "Auth token not found" });

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, function (err, decoded) {
    if (err) return res.status(403).send({ error: "Auth Failed" });

    req.user = decoded;
    next();
  });
}

function localVariable(req, res, next) {
  req.app.locals = {
    resetSession: false,
  };
  next();
}

module.exports = { authenticate, localVariable };
