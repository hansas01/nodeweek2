const express = require('express');
const User = require('../models/user');
const passport = require('passport');
const authenticate = require('../authenticate');

const router = express.Router();

// GET all users (admin-only)
router.route('/')
.get(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    User.find()
    .then(users => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(users);
    })
    .catch(err => next(err));
});

// User Signup
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

// User Login
router.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
    const token = authenticate.getToken({_id: req.user._id});
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.json({success: true, token: token, status: 'You are successfully logged in!'});
});

// User Logout
router.get('/logout', (req, res, next) => {
    if (req.session) {
        req.session.destroy();
        res.clearCookie('session-id');
        res.redirect('/');
    } else {
        const err = new Error('You are not logged in!');
        err.status = 401;
        return next(err);
    }
});

// GET, PUT, DELETE user by ID (admin-only)
router.route('/:userId')
.get(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    User.findById(req.params.userId)
    .then(user => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(user);
    })
    .catch(err => next(err));
})
.put(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    User.findByIdAndUpdate(req.params.userId, {
        $set: req.body
    }, { new: true })
    .then(user => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(user);
    })
    .catch(err => next(err));
})
.delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    User.findByIdAndDelete(req.params.userId)
    .then(response => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(response);
    })
    .catch(err => next(err));
});

module.exports = router;
