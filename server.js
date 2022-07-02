const express = require("express");
const app =express();
const {pool}=require("./dbConfig");
const bcrypt = require("bcrypt");
const flash = require("express-flash");
const session = require("express-session");
const passport = require("passport");
require("dotenv").config();

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended:false}));

const PORT=process.env.PORT || 4000;

const initializePassport = require("./passportConfig");
initializePassport(passport);

app.use(
    session({
       secret: "secret",
       resave: false,
       saveUninitialized: false
    })
  );

app.use(passport.initialize());
app.use(passport.session());

  app.use(flash());  

app.get("/",(req,res)=>{
    res.render("index");
});

app.get("/users/register",checkAuthenticated,(req,res)=>{
    res.render("register.ejs");
});


app.get("/users/login",checkAuthenticated,(req,res)=>{
    console.log(req.session.flash.error);
    res.render("login.ejs");
});

app.get("/users/dashboard",checkNotAuthenticated,(req,res)=>{
    console.log(req.isAuthenticated());
    res.render("dashboard.ejs",{user:req.user.name});
});

app.get("/users/logout",(req,res)=>{
    req.logOut(function(err) {
      if (err) { return next(err); }
      req.flash("sucess_msg","you Have logged Out");
      res.redirect('/');
    });
    });



app.post('/users/register',async(req,res)=>{
    let{name,email,pnumber,password,password2}=req.body;

    console.log ({
        name,email,pnumber,password,password2
    });
    let errors=[];
    if(!name || !email || !pnumber || !password || !password2){
        errors.push({message:"Please enter all Fields"});
    }
    if(password.length <6)
    {
        errors.push({message:"Password should be at least 6 Characteres"});
    } 
    if(password!=password2)
    {
        errors.push({message:"Password do not match"});
    } 
    if(errors.length>0){
        res.render("register",{errors, name, email,pnumber, password, password2});
    }
    else {
        hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users
              WHERE email = $1`,
            [email],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
        if (results.rows.length > 0) {
          return res.render("register", {
            message: "Email already registered"
          });
        } else {
          pool.query(
            `INSERT INTO users (name, email,phonenumber, password)
                VALUES ($1, $2, $3, $4)
                RETURNING id, password`,
            [name, email, pnumber,hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
}); 
app.post(
    "/users/login",
    passport.authenticate("local", {
      successRedirect: "/users/dashboard",
      failureRedirect: "/users/login",
      failureFlash: true
    })
  );

  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/users/dashboard");
    }
    next();
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
  }
app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`);
});