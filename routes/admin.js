const crypto = require('crypto');
const fs = require('fs');
const router = require('express').Router();
const cookieParser = require('cookie-parser');

router.use(cookieParser(process.env.COOKIE_SECRET));

router.get('/', (req, res) => {
  res.send('ADMIN');
});

router.get('/gen-keys', validateAdmin, async (req, res) => {
  // res.send('One Moment Please...');
  await genAccessKeyPair();
  await genRefreshKeyPair();
  return res.send('PUBLIC/PRIVATE KEYS CREATED');
});

router.get('/refresh-token', validateAdmin, (req, res) => {
  const cookieConfig = {
    httpOnly: true, // to disable accessing cookie via client side js
    //secure: true, // to force https (if you use it)
    maxAge: 1000000000, // ttl in ms (remove this option and cookie will die when browser is closed)
    signed: true // if you use the secret with cookieParser
  };
  res
    .cookie('id', 'c9996001-7d48-49d8-a7ba-622355306385', cookieConfig)
    .send('cookie sent');
});

router.get('/read-cookie', (req, res) => {
  // const signedCookies = req.signedCookies; // get signed cookies
  // console.log('signed-cookies:', signedCookies);
  const cookieFound = req.signedCookies.atk;
  if (!myTestCookie) return res.status(400).send('COOKIE ALTERED');
  return res.status(200).send('COOKIE VERIFIED ' + myTestCookie);
  // console.log('our test signed cookie:', myTestCookie);
  // res.send('get cookie');
});

router.get('/gen-cookie-secret', (req, res) => {
  const userId = 'c9996001-7d48-49d8-a7ba-622355306385';
  const cookieSecret = crypto.randomBytes(12).toString('hex');
  const cookieId = cookieSecret + '.' + userId;
  const splitter = cookieId.split('.');
  const newId = splitter[1];
  return res.status(201).send(newId);
});

function validateAdmin(req, res, next) {
  let isAdmin = true;
  if (
    isAdmin !== true ||
    isAdmin == null ||
    isAdmin === undefined ||
    typeof isAdmin !== 'boolean'
  )
    return res.status(401).send('UNAUTHORIZED');
  next();
}
/**
 * This module will generate a public and private keypair and save to current directory
 *
 * Make sure to save the private key elsewhere after generated!
 */

function genAccessKeyPair() {
  // Generates an object where the keys are stored in properties `privateKey` and `publicKey`
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096, // bits - standard for RSA keys
    publicKeyEncoding: {
      type: 'pkcs1', // "Public Key Cryptography Standards 1"
      format: 'pem' // Most common formatting choice
    },
    privateKeyEncoding: {
      type: 'pkcs1', // "Public Key Cryptography Standards 1"
      format: 'pem' // Most common formatting choice
    }
  });

  // Create the public key file
  // fs.writeFileSync(__dirname + 'keys/id_rsa_pub.pem', keyPair.publicKey);
  fs.writeFileSync('./keys/access_id_rsa_pub.pem', keyPair.publicKey);

  // Create the private key file
  // fs.writeFileSync(__dirname + './keys/id_rsa_priv.pem', keyPair.privateKey);
  fs.writeFileSync('./keys/access_id_rsa_priv.pem', keyPair.privateKey);
}

// Generate the keypair
// genKeyPair();

function genRefreshKeyPair() {
  // Generates an object where the keys are stored in properties `privateKey` and `publicKey`
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096, // bits - standard for RSA keys
    publicKeyEncoding: {
      type: 'pkcs1', // "Public Key Cryptography Standards 1"
      format: 'pem' // Most common formatting choice
    },
    privateKeyEncoding: {
      type: 'pkcs1', // "Public Key Cryptography Standards 1"
      format: 'pem' // Most common formatting choice
    }
  });

  // Create the public key file
  // fs.writeFileSync(__dirname + 'keys/id_rsa_pub.pem', keyPair.publicKey);
  fs.writeFileSync('./keys/refresh_id_rsa_pub.pem', keyPair.publicKey);

  // Create the private key file
  // fs.writeFileSync(__dirname + './keys/id_rsa_priv.pem', keyPair.privateKey);
  fs.writeFileSync('./keys/refresh_id_rsa_priv.pem', keyPair.privateKey);
}

// Generate the keypair
// genKeyPair();

module.exports = router;
