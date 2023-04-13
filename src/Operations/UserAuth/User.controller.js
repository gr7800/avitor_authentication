// Import the User model and required libraries
const UserModel = require('./User.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Login controller
exports.LoginController = async (req, res) => {
    // Extract email and password from request body
    const { email, password, secretKey} = req.body;
    try {
        // Find a user with the provided email in the database
        const userpersent = await UserModel.findOne({ email: email });
        const Admin = await UserModel.findOne({email:"cto.aviatorcloud@gmail.com"})
        console.log(userpersent)
        // If no user is found, send a 401 Unauthorized status code
        if (!userpersent) {
            return res.status(401).send({ message: 'Incorrect username' });
        }
        // Check if the password provided matches the hashed password in the database
        const isPasswordCorrect = await bcrypt.compare(password, userpersent.password);
        if (!isPasswordCorrect) {
            // If the password does not match, send a 401 Unauthorized status code
            return res.status(401).send({ message: 'Incorrect password' });
        }

        if(Admin.secretKey!=secretKey){
            return res.status(401).send({ message: 'Incorrect SecretKey' }); 
        }
        // If the email and password are correct, create a JWT token and send it to the client
        const token = jwt.sign(
            {
                email: userpersent.email,
                fullName: userpersent.fullName,
                _id: userpersent._id
            },
            process.env.JWT_SECRET,
            { expiresIn: '7 days' }
        );
        // Send a success response with the tokens and user data
        return res.status(200).send({ token, userpersent, message: 'Login successful' });
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};

//Get All User
exports.GetAllUser = async (req, res) => {
    // Extract email and password from request body
    let { token } = req.headers;
    console.log(token);
    let decode = jwt.decode(token, process.env.JWT_SECRET);
    try {
        if (decode.email!="cto.aviatorcloud@gmail.com") {
            return res.status(401).send({ message: 'You are unable access this feature' });
        }
        const AllUser = await UserModel.find();
        
        return res.status(200).send({user:AllUser});
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};

exports.GetSingalUser = async (req, res) => {
    // Extract email and password from request body
    let { token } = req.headers;
    let decode = jwt.decode(token, process.env.JWT_SECRET);
    try {
        const AllUser = await UserModel.findOne({email:decode.email});
        if(!AllUser){
            return res.status(401).send({message:"Please Login again"});  
        }
        return res.status(200).send({ token:token, userpersent:AllUser, message: 'Login successful' });
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};

// Signup controller
exports.RegisterController = async (req, res) => {
    // Extract name, email, and password from request body
    const { fullName, email, password, avatar, easyScore, mediumScore, hardScore,secretKey } = req.body;
    try {
        // Check if a user with the provided email already exists in the database
        const exsistinguser = await UserModel.findOne({ email });
        if (exsistinguser) {
            // If a user already exists, send a 409 Conflict status code
            return res.status(409).send({
                message: 'User already exists',
            });
        }
        // Hash the password and create a new user in the database
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await UserModel.create({
            fullName: fullName,
            email: email,
            password: hashedPassword,
            avatar: avatar,
            easyScore: easyScore,
            mediumScore: mediumScore,
            hardScore: hardScore,
            secretKey:email
        });
        // Send a success response with the newly created user data
        return res.status(201).send({
            user: newUser,
            message: 'User has register Successfully !',
        });
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};


// Update password controller
exports.UpdatePasswordController = async (req, res) => {
    // Extract the user ID and password from the request body
    const { oldPassword, newPassword } = req.body;
    let { token } = req.headers;
    let decode = jwt.decode(token, process.env.JWT_SECRET);
    try {
        // Find the user in the database by their ID
        const user = await UserModel.findOne({ email: decode.email });
        if (!user) {
            // If no user is found, send a 404 Not Found status code
            return res.status(404).send({ message: 'User not found or you are not loggedin' });
        }
        // Check if the old password provided matches the hashed password in the database
        const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);
        if (!isOldPasswordCorrect) {
            // If the old password does not match, send a 401 Unauthorized status code
            return res.status(401).send({ message: 'Incorrect old password' });
        }
        // Hash the new password and update the user's password in the database
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;
        await user.save();
        // Send a success response
        return res.status(200).send({ message: 'Password updated successfully' });
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};


// Profile Update controller
exports.ProfileUpdateController = async (req, res) => {
    // Extract user ID, full name, and avatar URL from request body
    const { email, avatar } = req.body;
    let { id } = req.params;
    try {
        // Find the user in the database by their ID
        let updateUser = await UserModel.findByIdAndUpdate({ _id: id },req.body);
        let newUser = await UserModel.findOne({_id:id});
        return res.status(200).send({ status: true, message: "user updated successfully",user:newUser });
    } catch (error) {
        // If an error occurs, send a 500 Internal Server Error status code with the error message
        return res.status(500).send(error.message);
    }
};

exports.deleteAuser = async (req, res) => {
    // Extract user ID, full name, and avatar URL from request body
    let { id } = req.params;
    console.log(id)
    try {
        let user = await UserModel.findByIdAndDelete({ _id: id });
        let alluser = await UserModel.find();
        return res.status(200).send({ status: true, message: "user deleted successfully",user:alluser });
    } catch (error) {
        console.log(error);
        return res.status(401).send({ status: false, message: "something went wrong" });
    }
};