'use strict';

var _ = require('lodash'),
    async = require('async'),
    cookieParser = require('cookie-parser'),
    mongoose = require('mongoose'),
    mysql = require('mysql'),
    CryptoJS = require("crypto-js"),
    passport = require('passport'),
    passportSocketIo = require('passport.socketio'),
    BearerStrategy = require('passport-http-bearer'),
    BasicStrategy = require('passport-http').BasicStrategy,
    settings = require('./../config'),
    plugins = require('./../plugins');

var connection = mysql.createConnection({
    host: '192.168.1.202',
    user: 'easycollab_test',
    password: '+)Y{1~(6@_{}5ql',
    database: 'easycollab_test'
});

var providerSettings = {},
    MAX_AUTH_DELAY_TIME = 24 * 60 * 60 * 1000,
    loginAttempts = {},
    enabledProviders = [];

function getProviders(core) {
    return settings.auth.providers.map(function (key) {
        var Provider;

        if (key === 'local') {
            Provider = require('./local');
        } else {
            Provider = plugins.getPlugin(key, 'auth');
        }

        return {
            key: key,
            provider: new Provider(settings.auth[key], core)
        };
    });
}

function setup(app, session, core) {

    enabledProviders = getProviders(core);

    enabledProviders.forEach(function (p) {
        p.provider.setup();
        providerSettings[p.key] = p.provider.options;
    });

    function tokenAuth(username, password, done) {
        if (!done) {
            done = password;
        }

        var User = mongoose.model('User');
        User.findByToken(username, function (err, user) {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            return done(null, user);
        });
    }

    passport.use(new BearerStrategy(tokenAuth));
    passport.use(new BasicStrategy(tokenAuth));

    passport.serializeUser(function (user, done) {
        done(null, user._id);
    });

    passport.deserializeUser(function (id, done) {
        var User = mongoose.model('User');
        User.findOne({ _id: id }, function (err, user) {
            done(err, user);
        });
    });

    app.use(passport.initialize());
    app.use(passport.session());

    session = _.extend(session, {
        cookieParser: cookieParser,
        passport: passport
    });

    var psiAuth = passportSocketIo.authorize(session);

    app.io.use(function (socket, next) {
        var User = mongoose.model('User');
        if (socket.request._query && socket.request._query.token) {
            User.findByToken(socket.request._query.token, function (err, user) {
                if (err || !user) {
                    return next('Fail');
                }

                socket.request.user = user;
                socket.request.user.loggedIn = true;
                socket.request.user.usingToken = true;
                next();
            });
        } else {
            psiAuth(socket, next);
        }

    });
}

function checkIfAccountLocked(username, cb) {
    var attempt = loginAttempts[username];
    var isLocked = attempt &&
        attempt.lockedUntil &&
        attempt.lockedUntil > Date.now();

    cb(isLocked);
}

function wrapAuthCallback(username, cb) {
    return function (err, user, info) {
        if (!err && !user) {

            if (!loginAttempts[username]) {
                loginAttempts[username] = {
                    attempts: 0,
                    lockedUntil: null
                };
            }

            var attempt = loginAttempts[username];

            attempt.attempts++;

            if (attempt.attempts >= settings.auth.throttling.threshold) {
                var lock = Math.min(5000 * Math.pow(2, (attempt.attempts - settings.auth.throttling.threshold), MAX_AUTH_DELAY_TIME));
                attempt.lockedUntil = Date.now() + lock;
                return cb(err, user, {
                    locked: true,
                    message: 'Account is locked.'
                });
            }

            return cb(err, user, info);

        } else {

            if (loginAttempts[username]) {
                delete loginAttempts[username];
            }
            cb(err, user, info);
        }
    };
}

function authenticate() {
    var req, username, cb;

    if (arguments.length === 4) {
        username = arguments[1];

    } else if (arguments.length === 3) {
        username = arguments[0];

    } else {
        username = arguments[0].body.username;
    }

    username = username.toLowerCase();

    if (arguments.length === 4) {
        req = _.extend({}, arguments[0], {
            body: {
                username: username,
                password: arguments[2]
            }
        });
        cb = arguments[3];

    } else if (arguments.length === 3) {
        req = {
            body: {
                username: username,
                password: arguments[1]
            }
        };
        cb = arguments[2];

    } else {
        req = _.extend({}, arguments[0]);
        req.body.username = username;
        cb = arguments[1];
    }

    const mysqlUserName = req.body.username;
    const salt = 'DYhG93b0qyJfIxghfgfghhfgwvniR2G0FgaC9mi';
    const mysqlPassword = CryptoJS.SHA1(salt + req.body.password, salt).toString();
    console.log('reqObj = ', req.body);
    connection.query('SELECT * FROM `users` WHERE `username` = ? and password = ?', [mysqlUserName, mysqlPassword], function (error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        console.log('results = ', results);

        if (error) {
            return cb(null, null, {
                message: 'Your username or password is not correct'
            });
        }
        if (!error) {
            var User = mongoose.model('User');
            User.find({ email: mysqlUserName }, function (errorResponse, userResponse) {
                if (errorResponse) {
                    return cb(null, null, {
                        message: 'Your username or password is not correct'
                    });
                }
                if (userResponse.length == 0) {
                    const nameArr = (mysqlUserName.replace('.email')).split('@');
                    let firstName = '';
                    let lastName = '';
                    if (nameArr.length > 0) {
                        firstName = nameArr[0];
                        lastName = nameArr[0];
                    }
                    if (nameArr.length > 1) {
                        lastName = nameArr[1];
                    }
                    let displayName = firstName[0] + lastName[0];
                    var data = {
                        provider: 'local',
                        username: mysqlUserName,
                        email: mysqlUserName,
                        password: req.body.password,
                        firstName: firstName,
                        lastName: lastName,
                        displayName: displayName
                    };
                    console.log('new user = ', data);
                    register('local', data, function (registerError, userObj) {
                        if (!registerError) {
                            furtherLogin(req, username, cb);
                        }
                    });
                } else {
                    furtherLogin(req, username, cb);
                }
            });
        }
    });
}

function furtherLogin(req, username, cb) {
    checkIfAccountLocked(username, function (locked) {
        if (locked) {
            return cb(null, null, {
                locked: true,
                message: 'Account is locked.'
            });
        }

        if (settings.auth.throttling &&
            settings.auth.throttling.enable) {
            cb = wrapAuthCallback(username, cb);
        }

        var series = enabledProviders.map(function (p) {
            var provider = p.provider;
            return function () {
                var args = Array.prototype.slice.call(arguments);
                var callback = args.slice(args.length - 1)[0];

                if (args.length > 1 && args[0]) {
                    return callback(null, args[0]);
                }

                provider.authenticate(req, function (err, user) {
                    if (err) {
                        return callback(err);
                    }
                    return callback(null, user);
                });
            };
        });

        async.waterfall(series, function (err, user) {
            cb(err, user);
        });
    });
}

function register(provider, userData, cb) {
    var User = mongoose.model('User');
    var user = new User({ provider: provider });

    Object.keys(userData).forEach(function (key) {
        user.set(key, userData[key]);
    });

    user.save(cb);
}

module.exports = {
    setup: setup,
    authenticate: authenticate,
    register: register,
    providers: providerSettings
};
