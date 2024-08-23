const express = require('express');
const User = require('../models/user');
const passport = require('passport'); //require the passport app for authentication
const authenticate = require('../authenticate');

const router = express.Router();

/* GET users listing. */
router.get('/', function(req, res) {
  res.send('respond with a resource');
});

router.post('/signup', async (req, res) => {
    try {
        const user = new User({ username: req.body.username });
        await User.register(user, req.body.password);

        if (req.body.firstname) {
            user.firstname = req.body.firstname;
        }
        if (req.body.lastname) {
            user.lastname = req.body.lastname;
        }

        await user.save();
        
        passport.authenticate('local')(req, res, () => {
            res.status(200).json({ success: true, status: 'Registration Successful!' });
        });
    } catch (err) {
        res.status(500).json({ err: err });
    }
});


router.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
    const token = authenticate.getToken({_id: req.user._id});
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.json({success: true, token: token, status: 'You are successfully logged in!'});
});

router.get('/logout', (req, res, next) => {
    if (req.session) {
        req.session.destroy();
        res.clearCookie('session-id');
        res.redirect('/');
    } else {
        const err = new Error('You are not loggied in!');
        err.status = 401;
        return next(err);
    }
});

module.exports = router;
