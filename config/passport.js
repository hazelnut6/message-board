const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const db = require('../db/pool');

module.exports = function(passport) { //is this named
    //LocalStrategy
    passport.use(
        new LocalStrategy({ passReqToCallback: true }, async (req, username, password, done) => {
            try {
                const { rows } = await db.query('SELECT * FROM users WHERE username = $1;', [username]);
                const user = rows[0];
                if(!user) {
                    req.flash('error', 'Incorrect username.')
                    return done(null, false);
                }

                const match = await bcrypt.compare(password, user.password);
                if(!match) {
                    req.flash('error', 'Incorrect password.')
                    return done(null, false);
                }

                return done(null, user);
            } catch(err) {
                return done(err);
            }
        })
    );

    //Session serialization
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    //Session deserialization
    passport.deserializeUser(async (id, done) => {
        try {
            const { rows } = await db.query('SELECT * FROM users WHERE id = $1;', [id]);
            const user = rows[0];

            if(!user) {
                return done(null, false);
            }

            done(null, user);
        } catch(err) {
            done(err);
        }
    });
};