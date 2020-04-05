const models = require('../models/index');
const cookieParser = require('cookie-parser');
const router = require('express').Router();
const moment = require('moment');
const fs = require('fs');
const { uuid } = require('uuidv4');

const utils = require('../lib/utils');

router.use(cookieParser(process.env.COOKIE_SECRET));

router.get('/', (req, res) => {
  console.log(
    moment()
      .add(5, 'minutes')
      .format('LLL')
  );
  res.send('AUTH ROUTES');
});

router.get('/protected', utils.authenticateToken, async (req, res) => {
  res.send('AUTHORIZED');
});

router.post('/login', async (req, res) => {
  // Destructure
  const { email, password } = req.body;

  // Extract User Details
  const user = await utils.getUserData('email', email);

  // Check  if email exists
  if (!user) return res.status(401).send('Email Address Not Found'); // Unauthorized

  // Check for valid password
  const passwordMatch = utils.validPassword(password, user.hash, user.salt);
  if (!passwordMatch) return res.status(401).send('Password Incorrect'); // Unauthorized

  try {
    // Create Access Token
    const accessToken = utils.issueJWTAccess(user);
    //res.header('access-token', accessToken);

    const accessCookieConfig = {
      httpOnly: true, // to disable accessing cookie via client side js
      //secure: true, // to force https (if you use it)
      maxAge: 120000, // 2 mins ttl in ms (remove this option and cookie will die when browser is closed)
      signed: true // if you use the secret with cookieParser
    };
    res.cookie('atk', accessToken, accessCookieConfig);

    // console.log('HEADER: ', accessToken);
    // const tokenId = uuid();
    // Create Refresh Token
    const refreshToken = utils.issueJWTRefresh(user);
    const newToke = await models.Token.create({
      id: uuid(),
      user_id: user.id,
      refresh_token: refreshToken,
      create_date: moment().format('LLL')
    });
    const refreshCookieConfig = {
      httpOnly: true, // to disable accessing cookie via client side js
      //secure: true, // to force https (if you use it)
      maxAge: 86400000, // 24 hrs ttl in ms (remove this option and cookie will die when browser is closed)
      signed: true // if you use the secret with cookieParser
    };
    res.cookie('rtk', refreshToken, refreshCookieConfig);

    res.status(200).json({
      success: true,
      accessTokenoken: accessToken,
      refreshToken: refreshToken
    });
    // res.redirect('http://localhost:5000/api/auth/protected');
  } catch (err) {
    console.log('Token Issuance Error: ', err.message);
  }
});

router.post('/register', async (req, res) => {
  // Destructure
  const { first_name, last_name, email, password } = req.body;

  // Check dor duplicate email
  let emailExists = await utils.isUserEmaill(email);
  if (emailExists) return res.status(400).send('Email Address Exists'); // BAD REQUEST

  // Generate Salt and Hash
  const saltHash = await utils.genPassword(password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;

  try {
    // Create New User
    const newUser = await models.User.create({
      id: uuid(),
      first_name,
      last_name,
      email,
      salt,
      hash,
      isAdmin: false
    });
    return res.status(201).json({
      message: 'Success',
      status: 201,
      user: newUser
    });
  } catch (err) {
    return res.status(500).json({
      message: 'Failed',
      status: 500,
      desc: err.message
    });
  }
});

router.get('/login', (req, res) => {
  res.render('login', { title: 'Login Page', head: 'Log In' });
});

router.get('/login3', (req, res) => {
  const expireDate = req.signedCookies.expires;
  if (!expireDate) return res.send('COOKIE ALTERED OR EXPIRED');

  const currDate = moment().format('LLL');
  if (currDate > expireDate) {
    res.send('TOKEN EXPIRED');
  } else {
    res.send('TOKEN GOOD');
  }

  res.end();
});

router.get('/login2', (req, res) => {
  const cookieConfig = {
    httpOnly: true, // to disable accessing cookie via client side js
    // secure: true, // to force https (if you use it)
    // expires: newTime,
    maxAge: 33000000, // 15 mins ttl in ms (remove this option and cookie will die when browser is closed)
    signed: true // if you use the secret with cookieParser
  };
  const currentTime = moment().format('LLL');
  const newTime = moment()
    .add(15, 'minutes')
    .format('LLL');
  console.log('CURRTIME--> ', currentTime);
  console.log('NEWTIME--> ', newTime);

  res.cookie('expires', newTime, cookieConfig);

  // const expiration = req.signedCookies.atx;
  // console.log('---> ', expiration);
  // const expiresAt = JSON.parse(expiration);
  // console.log('---> ', moment(expiresAt));

  res.end();
});

router.post('/login99', async (req, res, next) => {
  // let thirtyMinutes = 30 * 60 * 1000; // convert 30 minutes to milliseconds
  // let date1 = new Date();
  // let date2 = new Date(date1.getTime() + thirtyMinutes);
  // console.log('===> ', date1);
  // console.log('===> ', date2);

  // console.log(date2);
  const myTestCookie = req.signedCookies.id;

  // console.log('--> ', newTime.getMilliseconds());

  const { email, password } = req.body;
  const user = await models.User.findOne({
    attributes: ['id', 'hash', 'salt', 'isAdmin'],
    where: { email: email }
  });
  if (!user) {
    return res.status(401).json({ success: false, msg: 'could not find user' });
  }

  // return res.end();
  // Function defined at bottom of app.js
  const isValid = utils.validPassword(password, user.hash, user.salt);

  if (isValid) {
    const tokenObject = utils.issueJWT(user);

    const cookieConfig = {
      httpOnly: true, // to disable accessing cookie via client side js
      // secure: true, // to force https (if you use it)
      // expires: newTime,
      maxAge: 180000, // 3 min   ttl in ms (remove this option and cookie will die when browser is closed)
      signed: true // if you use the secret with cookieParser
    };

    const expires = moment().add(tokenObject.expiresIn);

    const expireTime = moment()
      .add(30, 'minutes')
      .format('LLL');
    // console.log('NEWTIME--> ', newTime);

    res.cookie('ato', tokenObject.token, cookieConfig);
    res.cookie('atx', expireTime, cookieConfig);

    res.status(200).json({
      success: true,
      token: tokenObject.token,
      expiresIn: tokenObject.expires
    });
  } else {
    res
      .status(401)
      .json({ success: false, msg: 'you entered the wrong password' });
  }
});

router.get('/register', (req, res) => {
  res.render('register', { title: 'Register Page', head: 'Register' });
});

module.exports = router;

const PUB_ACCESS_KEY = fs.readFileSync('./keys/access_id_rsa_pub.pem', 'utf8');
// At a minimum, you must pass the `jwtFromRequest` and `secretOrKey` properties
