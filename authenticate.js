const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
const config = require('./config.js');

// Add this line to import the Facebook strategy
const FacebookTokenStrategy = require('passport-facebook-token');

// Local strategy for username and password
exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// JWT strategy for handling token-based authentication
exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey, {expiresIn: 3600});
};

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(
    new JwtStrategy(
        opts,
        (jwt_payload, done) => {
            console.log('JWT payload:', jwt_payload);

            User.findOne({ _id: jwt_payload._id })
            .then((user) => {
              if (user) {
                return done(null, user);
              } else {
                return done(null, false);
              }
            }).catch((err) => done(err, false));
        }
    )
);

exports.verifyUser = passport.authenticate('jwt', {session: false});

// Middleware to verify if the user is an admin
exports.verifyAdmin = (req, res, next) => {
  if (req.user && req.user.admin) {
      return next();
  } else {
      const err = new Error("You are not authorized to perform this operation!");
      err.status = 403;
      return next(err);
  }
};

// Add the Facebook authentication strategy
exports.facebookPassport = passport.use(
  new FacebookTokenStrategy(
    {
      clientID: config.facebook.clientId,
      clientSecret: config.facebook.clientSecret
    },
    (accessToken, refreshToken, profile, done) => {
      User.findOne({ facebookId: profile.id }).then((user) => {
        if (user) {
          return done(null, user);
        } else {
          user = new User({ username: profile.displayName });
          user.facebookId = profile.id;
          user.firstname = profile.name.givenName;
          user.lastname = profile.name.familyName;
          user.save((err, user) => {
            if (err) {
              return done(err, false);
            } else {
              return done(null, user);
            }
          });
        }
      }).catch((err) => done(err, false));
    }
  )
);