const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyToken = async function (req, res, next) {
  const token = req.headers.token;
  console.log(token)

  if (!token) {
    return res.status(403).send("Unauthorized");
  }

  try {
    const verification = await jwt.verify(token, process.env.JWT_SECRET);
    if (verification) {
      console.log(verification)
      next();
    } else {
      return res.status(401).send("Operation not allowed.");
    }
  } catch (e) {
    return res.status(401).send(e.message);
  }
};

module.exports = verifyToken;