const express = require('express');
const User = require('./../models/user');
const router = express.Router();
const bcrypt = require('bcrypt');

// @TODO: Assignment here

router.post('/signin', async (req, res) => {
  const { username, password, rememberMe } = req.body;
  // @TODO: Complete user sign in
  // getting username and password from req.body
  try {
    // we have to check the username if it exist in db
    const user = await User.findOne({ username });

    // if it not exist we should pass an error to the response and return
    if (!user) {
      res.status(400).json('wrong username or password');
      return;
    }
    // if it exist we should check the password
    // bcrypt will do the compare for us with bcrypt.compare function
    const isValidPasswd = await bcrypt.compare(password, user.password_hash);

    // if the password is correct we set the header of user with our user.id
    // redirect to 'user/authenticated'

    if (isValidPasswd) {
      res.set('user', user.id);
      res.redirect('/user/authenticated');
    } else {
      res.status(400).json({ error: 'wrong username or password' });
      return;
    }
  } catch (error) {
    // Handle any potential errors during database interactions or validation
    console.error('Sign-in error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/signup', async (req, res) => {
  const {
    firstname,
    lastname,
    username,
    password,
    password2,
    acceptTos, // either "on" or undefined
    avatar,
  } = req.body;

  // firstly we are filling the requiremented fields and checking them are they filled up
  try {
    if (
      !acceptTos ||
      !username ||
      !password ||
      !firstname ||
      !lastname ||
      !password2
    ) {
      res.status(400).json({ error: 'missing required fields' });
      return;
    }
    const usedUsername = await User.findOne({ username });

    if (usedUsername) {
      res.status(400).json({ error: 'username already used' });
      return;
    }

    // if they are filled up we should check the password and password2 are they same
    if (password !== password2) {
      res.status(400).json({ error: 'passwords do not match' });
      return;
    } else {
      // if they are same we should hash the password and save it to db
      const salt = await bcrypt.genSalt();
      const password_hash = await bcrypt.hash(password, salt);
      const newUser = new User({
        firstname,
        lastname,
        username,
        password_hash,
        avatar,
      });
      await newUser.save();
      res.status(302).redirect('/user/authenticated');
    }
  } catch (error) {
    console.error('Sign-up error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }

  // @TODO: Complete user sign up
});

router.get('/signout', (req, res) => {
  // @TODO: Complete user sign out
});

// renders sign up page
router.get('/signup', (req, res) => {
  res.render('user/signup');
});

// renders sign in page
router.get('/signin', async (req, res) => {
  res.render('user/signin');
});

router.get('/authenticated', (req, res) => {
  res.render('user/authenticated');
});

module.exports = router;
