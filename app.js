import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRound = 10;
env.config();

app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      cookie: {
        maxAge: 1000*60*60,
      },
    })
  );

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DB,
    password: process.env.PG_PASS,
    port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res)=>{
    res.redirect("/login");
});
app.get("/login", (req, res)=>{
    res.render("login.ejs");
});
app.get("/signup", (req, res)=>{
    res.render("signup.ejs");
});
app.get("/logout", (req, res)=>{
    req.logout(function (err) {
        if (err) {
          return next(err);
        }
        res.redirect("/");
    });
});
app.get("/hello", (req, res) => {
    console.log(req.user);
    if (req.isAuthenticated()) {
      res.render("index.ejs");
    } else {
      res.redirect("/login");
    }
});
app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"],
    })
  );
  
  app.get("/auth/google/secrets", passport.authenticate("google", {
    successRedirect: "/hello",
    failureRedirect: "/login",
    })
  );
  
  app.post("/login", passport.authenticate("local", {
    successRedirect: "/hello",
    failureRedirect: "/login",
    })
  );
app.post("/signup", async (req, res)=>{
    const email = req.body.username;
    const password = req.body.password;

    try{
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1",[email]);
        if(checkResult.rows.length > 0){
            res.render("messege.ejs", {
              msg: "Username already exists, please log in :)",
              link: "/login",
              linkText: "Log in",
            });
        }else{
            bcrypt.hash(password, saltRound, async (err, hash)=>{
                if(err){
                    console.error(err);
                }else{
                    const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hash]);
                    const user = result.rows[0];
                    req.login(user, (err)=>{
                        if(err) console.log(err);
                        console.log("success");
                        res.redirect("/hello");
                    });
                }
            });
        }
    }catch(err){
        console.log(err);
    }
});
passport.use("local", new Strategy(async function verify(username, password, cb){
    try{
        const result = await db.query("SELECT * FROM users WHERE email = $1",[username]);
        if(result.rows.length > 0){
            const user = result.rows[0];
            const hashedPassword = user.password;
            bcrypt.compare(password, hashedPassword, (err, valid)=>{
                if(err){
                    console.error(err);
                    return cb(err);
                }else{
                    if(valid){
                        return cb(null, user);
                    }else{
                        return cb(null, false);
                    }
                }
            });
        }else{
            console.log("User not found");
            return cb(null, false);
        }   
    }catch(err){
        console.log(err);
    }
}));
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try{
        const result = await db.query("SELECT * FROM users WHERE email = $1",[profile.email]);
        if(result.rows.length === 0){
          const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)",[profile.email, "google"]);
          return cb(null, newUser.rows[0]);
        }else{
          return cb(null, result.rows[0]);
        }
      }catch(err){
        return cb(err);
      }
    }
  ));
  
  passport.serializeUser((user, cb) => {
    cb(null, user);
  });
  passport.deserializeUser((user, cb) => {
    cb(null, user);
  });

app.listen(port, ()=>{
    console.log(`Server running on port http://localhost:${port}`);
});