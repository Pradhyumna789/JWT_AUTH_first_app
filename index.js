// Dependencies:
// express: Web framework for Node.js.
// mongoose: MongoDB object modeling tool designed to work in an asynchronous environment.
// cookie-parser: Middleware to parse cookies attached to the client request object.
// jsonwebtoken: Library to generate and verify JSON Web Tokens.
// Using bcrypt for password hashing

// Database Setup:
// Connects to a MongoDB database named "Backend" running on mongodb://127.0.0.1:27017/.
// User Schema:
// Defines a User schema with fields for name, email, and password.

// Middleware:
// express.urlencoded: Middleware to parse incoming request bodies with urlencoded payloads.
// cookieParser: Middleware to parse cookies attached to the client request object.
// Authentication Middleware:
// isAuthenticated: Middleware function to verify if a user is authenticated by checking for a JWT token in the request cookies. If the token is present and valid, it decodes the token and attaches the user object to the request (req.user).

// Routes:
// /: Home route, requires authentication. Renders a logout page with the user's name.
// /register: Registration route. Renders a registration form.
// /login: Login route. Handles POST requests for user login. Upon successful login, sets a JWT token as a cookie and redirects to the home route.
// /logout: Logout route. Clears the JWT token cookie and redirects to the home route.

// Views:
// login.ejs: Login form with fields for name, email, and password.
// Functionality:
// Users can register with a name, email, and password.
// Registered users can log in with their email and password.
// Authentication is managed using JWT tokens stored as cookies.
// The system provides protection for certain routes by requiring users to be authenticated.
// Logout functionality clears the JWT token cookie.

import express from "express";
import mongoose, { mongo } from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"

// setting up express
const app = express();

// setting up the database connection and the schema
    mongoose.connect("mongodb://127.0.0.1:27017/", {
        dbName: "Backend"
    })
    .then(() => console.log("database connected"))
    .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

const User = mongoose.model("User", userSchema);

// setting up ejs for dynamic data loading
app.set("view engine", "ejs"); 

// Using MiddleWares - If we don't use middle ware to access the body's content using for example the post method then we would get an error "cannot read properties of undefined"
app.use(express.urlencoded( { extended: true } ));

// Setting up the cookie-parser middleware 
app.use(cookieParser());

// isAutenticated will act as a middleware
const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies; 
    if(token) {
        const decoded = jwt.verify(token, "secret"); // if we console.log(decoded) we get the actual user's id because jwt has decoded secret
        req.user = await User.findById(decoded._id);
        next();
    } else {
        res.render("login");
    }    
};

app.get("/", isAuthenticated, (req, res) => {
    // We can access cookies using something called as the "cookie parser" -> npm i cookie parser
    // const { token } = req.cookies; // or req.cookies.token
    res.render("logout", {name: req.user.name}); // rendering the user's name dynamically on the logout page using logout.ejs and the html tag <%= name %>
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    let user = await User.findOne({ email });
    if(!user) return res.redirect("/register");

    // const isMatch = user.password === password;
    // if(!isMatch) return res.render("login", { message: "Incorrect Password"  });
    // Instead of doing the above we can use bcrypt to compare the password
    const isMatch = await bcrypt.compare(password, user.password);

    const token = jwt.sign({_id: user._id}, "secret"); // npm i jwtwebtoken

    res.cookie("token", token, { // value of this cookie when logged in will token(user's id encoded as secret using jwt.sign() method)
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000), // This cookie is going to be expired in 60 minutes and that moment the user will be logged out automatically
    });

    res.redirect("/");
});

app.post("/register", async (req, res) => {

    const { name, email, password } = req.body;

    // If found no user with an email redirect to the action "/redirect"
    let user = await User.findOne({ email });
    if(user) {
        return res.redirect("/login"); // returning to exit this current function
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // For example the hashed password for "12345" is "$2b$10$e2InaCSQBWCcpZwmawJat.LMSqRQPYxPG/Nhlcf3e/hdLbwtxa3/C" which is stored in the database

    user = await User.create({
        name,
        email,
        password: hashedPassword,
    });

    const token = jwt.sign({_id: user._id}, "secret"); // npm i jwtwebtoken

    // httpOnly -> can access the cookie only on the client side and not the server side 
    // We could use jwt for authentication because we can't decode user's cookie's value i.e; id if you check the mongoDB's data in the mongoDB compass
    res.cookie("token", token, { // value of this cookie when logged in will token(user's id encoded as secret using jwt.sign() method)
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000), // This cookie is going to be expired in 60 minutes and that moment the user will be logged out automatically
    });

    // The next step is to request these cookies in "/"
    res.redirect("/");
});

app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    // res.clearCookie("token"); -> to remove the entire token cookie along with it's value
    res.redirect("/");
});

app.listen(5000, () => {
    console.log(`Server is working`);
})

