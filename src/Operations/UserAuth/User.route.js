// This is an Express router that defines the endpoints for User related routes.
const express = require("express");
const router = express.Router();
const {  LoginController, RegisterController, UpdatePasswordController, ProfileUpdateController, GetAllUser, deleteAuser } = require('./User.controller')

const tokenverify=require("../../Middleware/Authentication.Middleware")
router.get('/alluser',GetAllUser)
// Route for User Signup
router.post('/register', RegisterController)

// Route for User Login
router.post('/login', LoginController)

router.use(tokenverify);

// Route to update the password of user
router.patch('/updatepassword', UpdatePasswordController)

// Route to update the name of user
router.patch('/profileupdate/:id', ProfileUpdateController)
router.delete("/delete/:id",deleteAuser)
// Export the router to use in the main app.js file
module.exports = router;