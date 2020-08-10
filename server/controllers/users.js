const crypto = require('crypto');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const config = require('../config.js');
const qs = require('qs');

const authy = require('authy')(config.API_KEY);


function hashPW (pwd) {
    return crypto.createHash('sha256').update(pwd).digest('base64').toString();
}

/**
 * Login a user
 * @param req
 * @param res
 */
exports.login = function (req, res) {
    User.findOne({username: req.body.username})
        .exec(function (err, user) {
            if (!user) {
                err = 'Username Not Found';
            } else if (('password' in req.body) && (user.hashed_password !==
                hashPW(req.body.password.toString()))) {
                err = 'Wrong Password';
            } else {
                createSession(req, res, user);
            }

            if (err) {
                res.status(500).json(err);
            }
        });
};

/**
 * Logout a user
 *
 * @param req
 * @param res
 */
exports.logout = function (req, res) {
    req.session.destroy(function (err) {
        if (err) {
            console.log("Error Logging Out: ", err);
            return next(err);
        }
        res.status(200).send();
    });
};


/**
 * Check user login status.  Redirect appropriately.
 *
 * @param req
 * @param res
 */
exports.loggedIn = function (req, res) {

    if (req.session.loggedIn && req.session.authy) {
        res.status(200).json({url: "/protected"});
    } else if (req.session.loggedIn && !req.session.authy) {
        res.status(200).json({url: "/2fa"});
    } else {
        res.status(200).json({url: "/login"});
    }
};


/**
 * Sign up a new user.
 *
 * @param req
 * @param res
 */
exports.register = function (req, res) {

    let username = req.body.username;

    User.findOne({username: username}).exec(function (err, user) {
        if (err) {
            console.log('Rregistration Error', err);
            res.status(500).json(err);
            return;
        }
        if (user) {
            res.status(409).json({err: "Username Already Registered"});
            return;
        }

        console.log(user);

        user = new User({username: req.body.username});

        user.set('hashed_password', hashPW(req.body.password));
        user.set('email', req.body.email);
        user.set('authyId', null);
        user.save(function (err) {
            if (err) {
                console.log('Error Creating User', err);
                res.status(500).json(err);
            } else {

                authy.register_user(req.body.email, req.body.phone_number, req.body.country_code,
                    function (err, regRes) {
                        if (err) {
                            console.log('Error Registering User with Authy');
                            res.status(500).json(err);
                            return;
                        }

                        user.set('authyId', regRes.user.id);

                        // Save the AuthyID into the database then request an SMS
                        user.save(function (err) {
                            if (err) {
                                console.log('error saving user in authyId registration ', err);
                                res.session.error = err;
                                res.status(500).json(err);
                            } else {
                                createSession(req, res, user);
                            }
                        });
                    });
            }
        });
    });
};

/**
 * Request a OneCode via SMS
 *
 * @param req
 * @param res
 */
exports.sms = function (req, res) {
    let username = req.session.username;
    User.findOne({username: username}).exec(function (err, user) {
        console.log("Send SMS");
        if (err) {
            console.log('SendSMS', err);
            res.status(500).json(err);
            return;
        }

        /**
         * If the user has the Authy app installed, it'll send a text
         * to open the Authy app to the TOTP token for this particular app.
         *
         * Passing force: true forces an SMS send.
         */
        authy.request_sms(user.authyId, true, function (err, smsRes) {
            if (err) {
                console.log('ERROR requestSms', err);
                res.status(500).json(err);
                return;
            }
            console.log("requestSMS response: ", smsRes);
            res.status(200).json(smsRes);
        });
    });
};

/**
 * Request a OneCode via a voice call
 *
 * @param req
 * @param res
 */
exports.voice = function (req, res) {
    let username = req.session.username;
    User.findOne({username: username}).exec(function (err, user) {
        console.log("Send SMS");
        if (err) {
            console.log('ERROR SendSMS', err);
            res.status(500).json(err);
            return;
        }

        /**
         * If the user has the Authy app installed, it'll send a text
         * to open the Authy app to the TOTP token for this particular app.
         *
         * Passing force: true forces an voice call to be made
         */
        authy.request_call(user.authyId, true, function (err, callRes) {
            if (err) {
                console.error('ERROR requestcall', err);
                res.status(500).json(err);
                return;
            }
            console.log("requestCall response: ", callRes);
            res.status(200).json(callRes);
        });
    });
};

/**
 * Verify an Authy Code
 *
 * @param req
 * @param res
 */
exports.verify = function (req, res) {
    let username = req.session.username;
    User.findOne({username: username}).exec(function (err, user) {
        console.log("Verify Token");
        if (err) {
            console.error('Verify Token User Error: ', err);
            res.status(500).json(err);
        }


        authy.verify(user.authyId, req.body.token, function (err, tokenRes) {
            if (err) {
                console.log("Verify Token Error: ", err);
                res.status(500).json(err);
                return;
            }
            console.log("Verify Token Response: ", tokenRes);
            if (tokenRes.success) {
                req.session.authy = true;
            }
            res.status(200).json(tokenRes);
        });
    });
};


/**
 * Create the initial user session.
 *
 * @param req
 * @param res
 * @param user
 */
function createSession (req, res, user) {
    req.session.regenerate(function () {
        req.session.loggedIn = true;
        req.session.user = user.id;
        req.session.username = user.username;
        req.session.msg = 'Authenticated as: ' + user.username;
        req.session.authy = false;
        req.session.ph_verified = false;
        res.status(200).json();
    });
}