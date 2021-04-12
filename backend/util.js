import jwt from 'jsonwebtoken';
import config from './config';

const getToken = (user) => jwt.sign(
  {
    _id: user._id,
    name: user.name,
    email: user.email,
    isAdmin: user.isAdmin,
  },
  config.JWT_SECRET,
  {
    expiresIn: '48h',
  },
);

// eslint-disable-next-line consistent-return
const isAuth = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    const onlyToken = token.slice(7, token.length);
    // eslint-disable-next-line consistent-return
    jwt.verify(onlyToken, config.JWT_SECRET, (err, decode) => {
      if (err) {
        return res.status(401).send({ message: 'Invalid Token' });
      }
      req.user = decode;
      next();
    });
  } else {
    return res.status(401).send({ message: 'Token is not supplied.' });
  }
};

const isAdmin = (req, res, next) => {
  // eslint-disable-next-line no-console
  console.log(req.user);
  if (req.user && req.user.isAdmin) {
    return next();
  }
  return res.status(401).send({ message: 'Admin Token is not valid.' });
};

export { getToken, isAuth, isAdmin };
