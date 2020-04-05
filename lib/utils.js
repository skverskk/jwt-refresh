const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const router = express.Router();
const moment = require('moment');

const models = require('../models/index');

// router.use(cookieParser(process.env.COOKIE_SECRET));

// const PRIV_ACCESS_KEY = fs.readFileSync(
//   '../../keys/access_id_rsa_priv.pem',
//   'utf8'
// );

const PRIV_ACCESS_KEY = fs.readFileSync(
  './keys/access_id_rsa_priv.pem',
  'utf8'
);
const PRIV_REFRESH_KEY = fs.readFileSync(
  './keys/refresh_id_rsa_priv.pem',
  'utf8'
);

const PUB_ACCESS_KEY = fs.readFileSync('./keys/access_id_rsa_pub.pem', 'utf8');

const PUB_REFRESH_KEY = fs.readFileSync(
  './keys/refresh_id_rsa_pub.pem',
  'utf8'
);

// router.use(cookieParser(process.env.COOKIE_SECRET));

/**
 * -------------- HELPER FUNCTIONS ----------------
 */

/**
 *
 * @param {*} password - The plain text password
 * @param {*} hash - The hash stored in the database
 * @param {*} salt - The salt stored in the database
 *
 * This function uses the crypto library to decrypt the hash using the salt and then compares
 * the decrypted hash/salt with the password that the user provided at login
 */
function validPassword(password, hash, salt) {
  let hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
    .toString('hex');
  return hash === hashVerify;
}

const getUserById = async id => {
  return await models.User.findOne({
    attributes: ['id'],
    where: { id: id }
  });
};

async function isUserEmail(email) {
  let user = await models.User.findOne({
    attributes: ['email'],
    where: { email: email }
  });
  if (user) return true;
  return false;
}

/**
 *
 * @param {*} password - The password string that the user inputs to the password field in the register form
 *
 * This function takes a plain text password and creates a salt and hash out of it.  Instead of storing the plaintext
 * password in the database, the salt and hash are stored for security
 *
 * ALTERNATIVE: It would also be acceptable to just use a hashing algorithm to make a hash of the plain text password.
 * You would then store the hashed password in the database and then re-hash it to verify later (similar to what we do here)
 */
function genPassword(password) {
  let salt = crypto.randomBytes(32).toString('hex');
  let genHash = cryptomail
    .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
    .toString('hex');

  return {
    salt: salt,
    hash: genHash
  };
}

async function getUserData(emailOrId, emailOrIdValue) {
  let whereClause;
  if (emailOrId === 'email') {
    let whereClause = 'where: {email:' + emailOrIdValue + ')';
  } else if (emailOrId === 'id') {
    let whereClause = 'where: {id:' + emailOrIdValue + ')';
  } else {
    return false;
  }
  let user = await models.User.findOne({
    attributes: [
      'id',
      'first_name',
      'last_name',
      'email',
      'salt',
      'hash',
      'isAdmin'
    ],
    whereClause
  });
  if (!user) return false;
  return {
    id: user.id,
    first_name: user.first_name,
    last_name: user.last_name,
    email: user.email,
    salt: user.salt,
    hash: user.hash,
    isAdmin: user.isAdmin
  };
}
/**
 * @param {*} user - The user object.  We need this to set the JWT `sub` payload property to the MongoDB user ID
 */
function issueJWTAccess(user) {
  //   const id = user.id;
  const payload = {
    id: user.id
  };

  return jwt.sign(payload, PRIV_ACCESS_KEY, {
    algorithm: 'RS256',
    expiresIn: '2m'
  });
}

function issueJWTRefresh(user) {
  //   const id = user.id;
  const payload = {
    id: user.id
  };

  return jwt.sign(payload, PRIV_REFRESH_KEY, {
    algorithm: 'RS256',
    expiresIn: '24h' // 24 hrs
  });
}

async function authenticateToken(req, res, next) {
  // Extract access token from inside cookie
  const accessToken = req.signedCookies.atk;

  // Extract refresh token from inside cookie
  const refreshToken = req.signedCookies.rtk;
  // Check for cookie tampering or missing refresh cookie
  if (
    accessToken === false ||
    refreshToken === false ||
    refreshToken === undefined
  ) {
    // const refreshTokenData = await models.Token.findOne({
    //   attributes: ['id', 'refresh_token', 'revoke_date'],
    //   where: { user_id: req.user.id, refresh_token: refreshToken }
    // });
    // if (refreshTokenData) {
    //   const updateToken = await models.Token.updateToken(
    //     {
    //       revoke_date: moment().format('LLL')
    //     },
    //     { where: { refresh_token: refreshTokenData.refreshToken } }
    //   );
    // }
    res.clearCookie('atk');
    res.clearCookie('rtk');
    console.log('ACCESS/REFRESH TOKE ISSUE');
    return res.redirect(`${process.env.URL_ROOT}/api/auth/login`);
  }

  try {
    jwt.verify(
      refreshToken,
      PUB_REFRESH_KEY,
      { algorithm: 'RS256' },
      (err, user) => {
        if (err) {
          console.log(err.message);
          res.clearCookie('rtk');
          return res.redirect(`${process.env.URL_ROOT}/api/auth/login`);
        }
        req.user = user;
        // next();
      }
    );
  } catch (err) {
    console.log('ERR: ', err.message);
    return res.redirect(`${process.env.URL_ROOT}/api/auth/login`);
  }
  // Lookup Refresh Token
  const refreshTokenData = await models.Token.findOne({
    attributes: ['id', 'refresh_token', 'revoke_date'],
    where: { user_id: req.user.id, refresh_token: refreshToken }
  });
  if (refreshTokenData) {
    if (refreshTokenData.revoke_date === null) {
      issueJWTAccess(req.user.id);
      const accessCookieConfig = {
        httpOnly: true, // to disable accessing cookie via client side js
        maxAge: process.env.ACCESS_COOKIE_MAXAGE,
        //secure: true, // to force https (if you use it)
        // maxAge: 120000, // 2 mins ttl in ms (remove this option and cookie will die when browser is closed)
        signed: true
      };
      res.cookie('atk', accessToken, accessCookieConfig);
      next();
    }
  } else {
    res.clearCookie('rtk');
    return res.redirect(`${process.env.URL_ROOT}/api/auth/login`);
  }
  return res.redirect(`${process.env.URL_ROOT}/api/auth/login`);
}

//     jwt.sign(payload, PRIV_ACCESS_KEY, {
//       algorithm: 'RS256',
//       expiresIn: '5m'
//     });

//     const accessCookieConfig = {
//       httpOnly: true, // to disable accessing cookie via client side js
//       //secure: true, // to force https (if you use it)
//       maxAge: 300000, // 5 mins ttl in ms (remove this option and cookie will die when browser is closed)
//       signed: true // if you use the secret with cookieParser
//     };
//     res.cookie('atk', accessToken, accessCookieConfig);
//   } // endif access cookie === false

//   jwt.verify(
//     accessCookie,
//     PUB_ACCESS_KEY,
//     // accessTokenSignOptions,
//     (err, user) => {
//       if (err) return res.status(403).send('FORBIDDEN');
//       req.user = user;
//       next();
//     }
//   );

//   //   console.log('REFRESH COOKIE: ', refreshCookie);
//   // Create new access token
// }

// console.log('COOKIE: ', accToken);
//   res.header('access-token', cookieToken);
//  const authHeader = req.headers.authorization;
//  console.log('AUTH-HEADER:', authHeader);

// const accCookie = req.header('access-token');

//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1]; // Strip out the word Bearer plus space
//  console.log('TOKEN: ', accToken);
// if (accToken == null) return res.status(401).send('UNAUTHORIZED');

function clearCookies(req, res) {
  res.clearCookie('atk');
  res.clearCookie('rtk');
  next();
}

module.exports.validPassword = validPassword;
module.exports.genPassword = genPassword;
module.exports.issueJWTAccess = issueJWTAccess;
module.exports.issueJWTRefresh = issueJWTRefresh;
module.exports.getUserById = getUserById;
module.exports.isUserEmail = isUserEmail;
module.exports.getUserData = getUserData;
module.exports.authenticateToken = authenticateToken;
