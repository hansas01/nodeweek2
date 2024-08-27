const express = require('express');
const mongoose = require('mongoose');
const Campsite = require('../models/campsite');
const authenticate = require('../authenticate');


const campsiteRouter = express.Router();

campsiteRouter.route('/')
.get((req, res, next) => {
    Campsite.find()
    .populate('comments.author')
    .then(campsites => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(campsites);
    })
    .catch(err => next(err));
})
.post(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    Campsite.create(req.body)
    .then(campsite => {
        console.log('Campsite Created', campsite)
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(campsite);
    })
    .catch(err => next(err));
})
.put(authenticate.verifyUser, (req, res) => {
    res.statusCode = 403;
    res.end('PUT operation not supported on /campsites');
})
.delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    Campsite.deleteMany()
    .then(response => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(response);
    })
    .catch(err => next(err));
});

campsiteRouter.route('/:campsiteId')
    .get((req, res, next) => {
        Campsite.findById(req.params.campsiteId)
        .populate('comments.author')
        .then(campsite => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsite);
        })
        .catch(err => next(err));
    })
.post(authenticate.verifyUser, (req, res) => {
  res.statusCode = 403;
    res.end(`POST operation not supported on /campsites/${req.params.campsiteId}`);
})
.put(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    Campsite.findByIdAndUpdate(req.params.campsiteId, {
        $set: req.body
    }, {new: true})
    .then(campsite => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(campsite);
    })
    .catch(err => next(err));
    })
.delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    Campsite.findByIdAndDelete(req.params.campsiteId)
    .then(response => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.json(response);
    })
    .catch(err => next(err));
});

campsiteRouter.route('/:campsiteId/comments')
    .get((req, res, next) => {
        Campsite.findById(req.params.campsiteId)
        .populate('comments.author')
        .then(campsite => {
            if (campsite) {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(campsite.comments);
            } else {
                err = new Error(`Campsite ${req.params.campsiteId} not found`);
                err.status = 404;
                return next(err);
            }
        })
        .catch(err => next(err));
    })
    .post(authenticate.verifyUser, (req, res, next) => {
        Campsite.findById(req.params.campsiteId)
        .then(campsite => {
            if (campsite) {
                req.body.author = req.user._id;
                campsite.comments.push(req.body);
            campsite.save()
            .then(campsite => {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(campsite);
            })
            .catch(err => next(err));
        } else {
            err = new Error(`Campsite ${req.params.campsiteId} not found`);
            err.status = 404;
            return next(err);
        }
    })
    .catch(err => next(err));
    })
.put(authenticate.verifyUser, (req, res) => {
    res.statusCode = 403;
    res.end(`PUT operation not supported on /campsites/${req.params.campsiteId}/comments`);
})
.delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
    Campsite.findById(req.params.campsiteId)
    .then(campsite => {
        if (campsite) {
            for (let i = (campsite.comments.length-1); i >= 0; i--) {
                campsite.comments.id(campsite.comments[i]._id).deleteOne();
            }
            campsite.save()
            .then(campsite => {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(campsite);
            })
            .catch(err => next(err));
        } else {
            err = new Error(`Campsite ${req.params.campsiteId} not found`);
            err.status = 404;
            return next(err);
        }
    })
    .catch(err => next(err));
});

campsiteRouter.route('/:campsiteId/comments/:commentId')
.get((req, res, next) => {
    Campsite.findById(req.params.campsiteId)
    .populate('comments.author')
    .then(campsite => {
        if (campsite && campsite.comments.id(req.params.commentId)) {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsite.comments.id(req.params.commentId));
        } else if (!campsite) {
            const err = new Error(`Campsite ${req.params.campsiteId} not found`);
            err.status = 404;
            return next(err);
        } else {
            const err = new Error(`Comment ${req.params.commentId} not found`);
            err.status = 404;
            return next(err);
        }
    })
    .catch(err => next(err));
})
.post(authenticate.verifyUser, (req, res) => {
    res.statusCode = 403;
    res.end(`POST operation not supported on /campsites/${req.params.campsiteId}/comments/${req.params.commentId}`);
})
.put(authenticate.verifyUser, (req, res, next) => {
    Campsite.findById(req.params.campsiteId)
    .then(campsite => {
        if (campsite && campsite.comments.id(req.params.commentId)) {
            const comment = campsite.comments.id(req.params.commentId);

            // Check if the logged-in user is the author of the comment
            if (comment.author.equals(req.user._id) || req.user.admin) {
                if (req.body.rating) {
                    comment.rating = req.body.rating;
                }
                if (req.body.text) {
                    comment.text = req.body.text;
                }
                campsite.save()
                .then(campsite => {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.json(campsite);
                })
                .catch(err => next(err));
            } else {
                res.statusCode = 403;
                res.end('You are not authorized to update this comment.');
            }
        } else if (!campsite) {
            const err = new Error(`Campsite ${req.params.campsiteId} not found`);
            err.status = 404;
            return next(err);
        } else {
            const err = new Error(`Comment ${req.params.commentId} not found`);
            err.status = 404;
            return next(err);
        }
    })
    .catch(err => next(err));
})
.delete(authenticate.verifyUser, (req, res, next) => {
    Campsite.findById(req.params.campsiteId)
    .then(campsite => {
        if (campsite && campsite.comments.id(req.params.commentId)) {
            const comment = campsite.comments.id(req.params.commentId);

            // Log the user and comment details for debugging
            console.log('User:', req.user);
            console.log('Comment Author:', comment.author);
            console.log('Comment Author ID:', comment.author.equals(req.user._id));
            console.log('User is Admin:', req.user.admin);

            // Check if the logged-in user is the author of the comment or an admin
            if (comment.author.equals(req.user._id) || req.user.admin) {
                // Remove the comment from the comments array
                Campsite.updateOne(
                    { _id: req.params.campsiteId },
                    { $pull: { comments: { _id: req.params.commentId } } }
                )
                .then(result => {
                    // Log the result for debugging
                    console.log('Update Result:', result);

                    if (result.modifiedCount > 0) {
                        // Successfully removed the comment
                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.json({ message: 'Comment deleted successfully' });
                    } else {
                        // If no document was modified, the comment might not have been found
                        const err = new Error(`Comment ${req.params.commentId} not found`);
                        err.status = 404;
                        return next(err);
                    }
                })
                .catch(err => next(err));
            } else {
                res.statusCode = 403;
                res.end('You are not authorized to delete this comment.');
            }
        } else if (!campsite) {
            const err = new Error(`Campsite ${req.params.campsiteId} not found`);
            err.status = 404;
            return next(err);
        } else {
            const err = new Error(`Comment ${req.params.commentId} not found`);
            err.status = 404;
            return next(err);
        }
    })
    .catch(err => next(err));
});


module.exports = campsiteRouter;