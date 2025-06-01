require('dotenv').config();
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const db = require('./db/pool');
const { error } = require('node:console');
require('./config/passport')(passport);
const flash = require('connect-flash');
const { title } = require('node:process');


const app = express();


//VIEW ENGINE
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


//MIDDLEWARE
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false, 
    saveUninitialized: false,
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());


//GLOBAL MIDDLEWARE FOR USER
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    next();
});


//ROUTES
app.get('/', async (req, res, next) => {
    try {
        //fetch messages from database
        const { rows: fetchedMessages } = await db.query(`
                SELECT 
                    m.id,
                    m.title,
                    m.text_content,
                    m.timestamp,
                    u.username AS author_username,
                    u.first_name AS author_first_name,
                    u.last_name AS author_last_name
                FROM messages AS m
                JOIN users AS u ON m.user_id = u.id
                ORDER BY m.timestamp DESC;
            `); 

            res.render('index', {
                title: 'Anonymous Message Board',
                messages: fetchedMessages,
                flashMessages: {
                    success: req.flash('success'),
                    error: req.flash('error')
                }
            });
    } catch(err) {
        return next(err);
    }
});
app.get('/sign-up', (req, res) => { //GET sign-up
    res.render('sign-up', { errors: [], user_data: {} });
});
app.post('/sign-up', //POST sign-up
    [
        //Sanitization & validation
        body('first_name')
            .trim()
            .isLength({ min: 1 }).withMessage('First name is required.')
            .escape(),
        body('last_name')
            .trim()
            .isLength({ min: 1 }).withMessage('Last name is required.')
            .escape(),
        body('username')
            .trim()
            .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long.')
            .escape(),
        body('password')
            .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
        body('confirm_password').custom((value, { req }) => {
            if(value !== req.body.password) {
                throw new Error('Password confirmation does not match password.');
            }

            return true;
        })
    ],
    async (req, res, next) => {
        //Validation errors
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.render('sign-up', {
                errors: errors.array(),
                user_data: req.body
            });
        }

        try {
            //Password hashing
            const hashedPassword = await bcrypt.hash(req.body.password, 10);

            //Insert users to db
            const result = await db.query(
                "INSERT INTO users (first_name, last_name, username, password, is_member, is_admin) VALUES ($1, $2, $3, $4, FALSE, FALSE) RETURNING *;",
                [req.body.first_name, req.body.last_name, req.body.username, hashedPassword]
            );

            //log in automatically after sign up
            req.login(result.rows[0], (err) => {
                if(err) { return next(err); }
                res.redirect('/')
            })
        } catch(err) {
            console.error("Error signing up user:", err);
            if (err.code === '23505' && err.detail.includes('username')) {
                return res.render('sign-up', {
                    errors: [{ msg: 'That username (email) is already registered.' }],
                    user_data: req.body
                });
            }
            return next(err);
        }
    }
);
app.get('/log-in', (req, res) => { //GET log in
    res.render('log-in', { messages: req.flash('error') });
});
app.post('/log-in', //POST log in
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/log-in',
        failureMessage: true
    })
);
app.get('/log-out', (req, res, next) => { //GET log-out
    req.logout((err) => {
        if(err) {
            return next(err);
        }
        res.redirect('/');
    });
});
//Authentication middleware(create message)
function isAuthenticated(req, res, next) {
    if(req.isAuthenticated()) {
        return next();
    }
    res.redirect('/log-in');
}
app.get('/create-message', isAuthenticated, (req, res) => { //GET create-message
    res.render('create-message', { errors: [], message_data: {} });
});
app.post('/create-message', isAuthenticated, //POST create-message
    [
        body('title')
            .trim()
            .isLength({ min: 1 }).withMessage('Title is required.')
            .isLength({ max: 255 }).withMessage('Title cannot exceed 255 characters.')
            .escape(),
        body('text_content')
            .trim()
            .isLength({ min: 1 }).withMessage('Message content is required.')
            .escape()
    ],
    async(req, res, next) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.render('create-message', {
                errors: errors.array(),
                message_data: req.body
            });
        }

        try{
            //Insert msg to db
            const result = await db.query(
                'INSERT INTO messages (title, text_content, user_id) VALUES ($1, $2, $3) RETURNING *;',
                [req.body.title, req.body.text_content, req.user.id]
            );

            res.redirect('/');
        } catch(err) {
            console.error('Error creating message:', err);
            return next(err);
        }
    }
);
//Check if user is authenticated AND not already a member
function isNotMember(req, res, next) {
    if(req.isAuthenticated() && !req.user.is_memeber) {
        return next();
    }
    res.redirect(req.isAuthenticated() ? '/' : '/log-in');
}
app.get('/be-member', isNotMember, (req, res) => { //GET be-member
    res.render('be-member', { errors: [] });
});
app.post('/be-member', isNotMember, //POST be-member
    [
        body('passcode')
            .trim()
            .isLength({ min: 1 }).withMessage('Passcode is required.')
            .escape()
    ],
    async (req, res, next) => {
        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.render('be-member', { errors: errors.array() });
        }

        const MEMBER_PASSCODE = process.env.MEMBER_PASSCODE;
        if(req.body.passcode !== MEMBER_PASSCODE) {
            return res.render('be-member', { errors: [{ msg: 'Incorrect passcode. Please try again.' }] });
        }

        try {
            await db.query(
                'UPDATE users SET is_member = TRUE WHERE id = $1;',
                [req.user.id]
            );

            req.login(req.user, (err) => {
                if(err) { return next(err); }
                res.redirect('/');
            });

        } catch(err) {
            console.error('Error updating membership status:', err);
            return next(err);
        }
    }
);
//Check if user is authenticated AND NOT already an admin
function isNotAdmin(req, res, next) {
    if(req.isAuthenticated() && !req.user.is_admin) {
        return next();
    }

    res.redirect(req.isAuthenticated() ? '/' : '/log-in');
}
app.get('/be-admin', isNotAdmin, (req, res) => { //GET be-member
    res.render('be-admin', { errors: [] });
});
app.post('/be-admin', isNotAdmin, // POST be-member
    [
        body('passcode')
            .trim()
            .isLength({ min: 1 }).withMessage('Passcoded is required.')
            .escape()
    ],
    async (req, res, next) => {
        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.render('be-admin', { errors: errors.array() });
        }

        const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE;
        if(req.body.passcode !== ADMIN_PASSCODE) {
            res.render('be-admin', { errors: [{ msg: 'Incorrect admin passcode. Please try again.' }] });
        }

        try {
            await db.query(
                'UPDATE users SET is_admin = TRUE WHERE id = $1;',
                [req.user.id]
            );

            req.login(req.user, (err) => {
                if(err) { return next(err); }
                res.redirect('/');
            });
        } catch(err) {
            console.error('Error updating admin status:', err);
            return next(err);
        }
    }
);
//Check if user is authenticated AND is an admin
function isAdmin(req, res, next) {
    if(req.isAuthenticated() && req.user.is_admin) {
        return next();
    }
    res.redirect('/');
}
// POST /message/:id/delete route: Handle message deletion (Admin Only)
app.post('/message/:id/delete', isAdmin, async (req, res, next) => {
    try {
        const messageId = req.params.id;
        await db.query('DELETE FROM messages WHERE id = $1;', [messageId]);

        //Add success flash message
        req.flash('success', 'Message deleted successfully!');
        res.redirect('/');
    } catch(err) {
        console.error('Error deleting message:', err);

        //Add error flash message
        req.flash('error', 'Therer was an error deleting the message.');
        return next(err);
    }
});


//START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));


//BASIC ERROR
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});