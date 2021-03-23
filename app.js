//jshint esversion:6

require('dotenv').config(); // we require this module so that we can store our private data in .env file which is hidden file
const express = require("express");
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

// require the below 3 modules for creating cookies and sessions in our website
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');


// first method is to encrypt the password but it is not so secure
//const encrypt = require('mongoose-encryption');       /require this module for password encryption

// second method is to hash the message using "md5" and it is more secure than the above one but has drawbacks too
//const md5 = require('md5');       // we use this package to hash our passwords with md5.

// third method is to hash passwords using "bcrypt" library and it is more secure than the above two
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();

// in order to use template, I have to install ejs-module
// this line is important if I want to use template
// Anything that is valid code in html document, all will be applicable in ejs file too
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

// I have pushed all my static files to the public folder and defined here using express
app.use(express.static("public"));

// initialise passport and session modules here
app.use(session({
  secret: 'my little secret.',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// connecting mongoose with localhost of mongoDB
mongoose.connect('mongodb://localhost/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

// in mongoose, everything is derived from a schema so firstly I am making schema here
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String
});

// now use passportLocalMongoose as a plugin to userSchema
userSchema.plugin(passportLocalMongoose);

// following is the code to apply encryption but this method is NOT so secure :-
// During save(), it will encrypt documents and then signed. During find(), it will authenticate documents and then decrypted

// firstly I have to set my encryption key. I have stored that key in .env file
// Schemas are "pluggable", that is, they allow for applying pre-packaged capabilities to extend their functionality
// You can also specify exactly which fields to encrypt with the "encryptedFields" option.
// here I want to encrypt only my password field

// I can grab value of secret key from .env file by writing "process.env.SECRET"
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });


// now compiling our userSchema into a model
// here we have to mention singular form of our collection and starts with capital letter that's why I have written "Item" just
// mongoose will automatically conver this collection into plural form and converts first letter to lowercase i.e. "items"
const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req,res){
  res.render("home");   //rendering home.ejs file
});

app.get("/register", function(req,res){
  res.render("register");   //rendering register.ejs file
});

app.get("/login", function(req,res){
  res.render("login");    //rendering login.ejs file
});

app.get("/secrets", function(req, res){
  // here I am finding those users in my database whose secret field is not NULL means that users who has submitted their secrets
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {userWithSecrets: foundUsers});
      }
    }
  });

});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){      //here we check whether cookie is already creatd means user's session is not timed out yet
    res.render("submit");
  }else{
    res.redirect("/login");
  }
})
// remember that whenever we save our app.js file, our server gets started automatically due to nodemon and all my cookies get deleted automatically

app.get("/logout", function(req, res){
  req.logout();        // it will delete all the cookies
  res.redirect("/");   // and redirect to the home route
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  // here "req.user" will return id and username of that user who makes a post request on /submit route

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  });

});

app.post("/register", function(req,res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
        // here I am creating cookie for the newUser and redirects them to /secrets route
        passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});


app.post("/login", function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
        // when users login to my website then I immediately create cookie for him and started his session
        passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");  // and redirects them to the secrets route
      });
    }
  });

});


app.listen(3000, function(){
  console.log("server is running at 3000");
})

// whatever route is specified in "action" attribute in register.ejs file that same route we have to mention here
// We are not using the below method here to handle post request on /register route

// app.post("/register", function(req,res){
  //   // creating new document User collection
  //   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     // Store hash in your userDB database
    //     const newUser = new User({
      //        email: req.body.username,
      //        password: hash
      //     });
      //
      //     newUser.save(function(err){
        //       if(err){
          //         console.log(err);
          //       }else{
            //         res.render("secrets"); //rendering secrets.ejs file
            //       }
            //     });
            //   });
            // });

            // whatever route is specified in "action" attribute in login.ejs file that same route we have to mention here
            // We are not using the below method here to handle post request on /login route

            // app.post("/login", function(req,res){
              //   const enteredUsername = req.body.username;
              //   const enteredPassword = req.body.password;
              //
              //   // here in curly bracket, I have specified my condition that whether enteredUsername is matching with one of the email that I have stored in my database or not
              //   User.findOne({email: enteredUsername}, function(err, foundUser){
                //     if(err){
                  //       console.log(err);
                  //     }else{
                    //       if(foundUser){
                      //         // Load hash from my userDB database
                      //         bcrypt.compare(enteredPassword, foundUser.password, function(err, result) {
                        //             if(result===true){ //means password matches
                          //               res.render("secrets");
                          //             }
                          //         });
                          //       }
                          //     }
                          //   });
                          // });
