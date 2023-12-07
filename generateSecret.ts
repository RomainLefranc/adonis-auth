import crypto from "crypto"

const generateJwtSecret = () => {
  return crypto.randomBytes(32).toString('hex'); // 32 bytes for a 256-bit key
};

const jwtSecret = generateJwtSecret();
console.log('Generated JWT Secret:', jwtSecret);
