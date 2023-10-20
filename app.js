require('dotenv').config()

const express = require("express");
const mongodb = require("mongodb");
const mongoose = require("mongoose");
const path = require("path");
const bodyParser = require("body-parser");
const app = express();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const PORT = process.env.PORT || 8000;
const uri = process.env.MONGODB_URI;
const publicPath = path.join(__dirname, "/public");
const viewsPath = path.join(__dirname, "/views");

app.use(bodyParser.urlencoded({
  extended: true
}));

app.set("view engine", 'ejs');
app.use(express.static(publicPath));
app.set("views", viewsPath);

app.use(session({
  secret: "our little secret.",
  resave: false,
  saveUninitialized: false
}))


app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(uri, {
  useNewUrlParser: true
});

const userInfoSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId : String,
  githubId :String
})

userInfoSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
userInfoSchema.plugin(findOrCreate);

const UserInfo = mongoose.model('UserInfo', userInfoSchema);

passport.use(UserInfo.createStrategy());


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});



passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:8000/auth/google/profile",
  useProfileURL: "https://www.gogleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  UserInfo.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'http://localhost:8000/auth/github/profile'
}, function(accessToken, refreshToken, profile, done) {
  UserInfo.findOrCreate({ githubId: profile.id }, function(err, user) {
    return done(err, user);
  });
}));


app.get("/", (req, res) => {
  res.render("index");
})

app.get("/auth/google", (req, res) =>{
   passport.authenticate("google", {scope : ["profile"]})(req, res);
})

app.get("/auth/google/profile", 
   passport.authenticate("google", {failureRedirect:"/"}),
   function(req, res){
    res.redirect("/profile");
   }

);

app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/profile',
  passport.authenticate('github', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/profile');
  }
);



app.get("/login", (req, res) => {
  res.render("login", {
    errorMsg: "",
    hasError: false
  });
})

app.get("/signUp", (req, res) => {
  res.render("index");
})

app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("profile");
  } else {
     res.redirect('/');
  }
})

app.get("/logout", function(req, res){

   req.logout(function(err){
    if(err){
       console.log(err);
    }
    res.redirect('/');
   });

  
});



app.post("/register", (req, res) => {
 
  UserInfo.register({email: req.body.email}, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect('/');
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/profile");
      });

    }

  });


});


app.post('/login', async (req, res) => {

  const user = new UserInfo({
    email: req.body.email,
    password: req.body.password
  })

  req.logIn(user, function (err) {
    if (err) {
     console.log(err);
    } 
    else {
      passport.authenticate("local", function (err, user, info) {
        if (err) {
          console.error(err);
        }
        if (!user) {
          // Authentication failed, render the login page with an error message
          return res.render('login', {
            errorMsg: 'Invalid email or password',
            hasError: true
          });
        }
      })(req, res, function () {
          res.redirect("/profile");

      })

    }
  })

});



app.listen(PORT, () => {
  console.log(`listening to the ${PORT}`);
})