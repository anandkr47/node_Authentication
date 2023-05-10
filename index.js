const express = require("express");
const app = express();
const path = require("path");
const hbs = require("hbs");
const collection = require("./src/mongodb");
const session = require("express-session");
const nodemailer = require('nodemailer');
const authRouter = require('./src/controllers/google-auth');
//const facebookRouter = require('./src/controllers/facebook-auth');
//const githubRouter = require('./src/controllers/github-auth');
const protectedRouter = require('./src/controllers/protected-route');
const passport = require('passport');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const saltRounds = 10;

// Set up express to use hbs as the view engine


app.use(express.json());
app.set("view engine", "hbs");
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, cb) {
  cb(null, user);
});
passport.deserializeUser(function (obj, cb) {
  cb(null, obj);
});

/*app.get('/', (req, res) => {
  res.render('auth');
});*/

app.use('/auth/google', authRouter);
//app.use('/auth/facebook', facebookRouter);
//app.use('/auth/github', githubRouter);
app.use('/protected', protectedRouter);
// Set views directory


// Middleware to check if user is logged in
function checkAuth(req, res, next) {
  if (req.session && req.session.isLoggedIn) {
    return next();
  } else {
    return res.redirect("/login");
  }
}

// Routes
app.get("/", checkAuth, (req, res) => {
  const { name, email, id } = req.session;
  res.render("home", { name, email, id });
});

app.get("/login", (req, res) => {
  res.render("login");
});


// Route to render the register form
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the email is already registered
    const existingUser = await collection.findOne({ email });
    if (existingUser) {
      return res.render("register", { error: "Email already registered" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const data = {
      name,
      email,
      password: hashedPassword,
    };

    // Insert the user into the database
    await collection.insertMany(data);
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    return res.render("register", { error: "Error registering user" });
  }
});


// Route to render the login form
app.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // Find user with given email using mongodb
  const user = await collection.findOne({ email });

  // Check if user exists and password is correct
  if (user && await bcrypt.compare(password, user.password)) {
    // Set session variable isLoggedIn to true
    req.session.isLoggedIn = true;
    req.session.email = user.email;
    req.session.name = user.name;
    res.redirect("/");
  } else {
    res.render("login", { error: "Invalid credentials", message: "Incorrect email or password. Please try again." });
  }
});


app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
  const email = req.body.email;

  // Check if the email exists in the database
  const user = await collection.findOne({ email });
  if (!user) {
   res.render("forgot-password", { message: "Email not found." });
  }

  // Generate a random token for password reset
  const token = crypto.randomBytes(20).toString('hex');

  // Store the token in the database along with the user's email
  await collection.updateOne({ email }, { $set: { resetToken: token } });

  // Send an email to the user containing a link to the password reset page
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'computerengineeres4@gmail.com',
      pass: process.env.APP_PASSWORD
    }
  });

  const mailOptions = {
    from: 'computerengineeres4@gmail.com',
    to: email,
    subject: 'Password Reset',
    text: `Please click on the following link to reset your password: https://node-authentication-2sau.onrender.com/update-password?token=${token}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
     res.render("forgot-password", { message: "Error sending Email." });
    } else {
      console.log('Email sent: ' + info.response);
       res.render("forgot-password", { message: "Email sent successfully." });
    }
  });
});


// ...
// Route to render the update password form
app.get('/update-password', (req, res) => {
  res.render('update-password', { message: req.query.message });
});

// Route to handle updating the password
app.post('/update-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  // Check if the new password and confirm password match
  if (newPassword !== confirmPassword) {
    return res.redirect('/update-password?message=New%20password%20and%20confirm%20password%20do%20not%20match');
  }

  try {
    // Find the user in the database based on the email
    const user = await collection.findOne({ email });
    if (!user) {
      return res.redirect('/update-password?message=User%20not%20found');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    await collection.updateOne({ email }, { password: hashedPassword });

    return res.redirect('/update-password?message=Password%20updated%20successfully');
  } catch (error) {
    console.error(error);
    return res.redirect('/update-password?message=Error%20updating%20password');
  }
});

// ...

app.post("/logout", (req, res) => {
  // Destroy the session and redirect to login page
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/login");
    }
  });
});
app.get('/reset-password', (req, res) => {
  res.render('reset-password');
});

app.post('/reset-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  try {
    // Find the user by email
    const user = await collection.findOne({ email });

    if (!user) {
      return res.render('reset-password', { message: 'User not found' });
    }

    // Check if the old password matches the stored password
    const isPasswordMatch = await bcrypt.compare(oldPassword, user.password);
    console.log(isPasswordMatch);
    if (!isPasswordMatch) {
      return res.render('reset-password', { message: 'Incorrect old password' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    await collection.findOneAndUpdate({ email }, { $set: { password: hashedPassword } });

    return res.render('reset-password', { message: 'Password updated successfully' });
  } catch (error) {
    console.error(error);
    return res.render('reset-password', { message: 'Internal server error' });
  }
});


app.listen(3000, () => {
  console.log("connected at port 3000");
});
