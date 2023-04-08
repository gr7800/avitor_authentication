// Require the Mongoose library.
const mongoose = require("mongoose");

// Define the user schema with fields for full name, user name, email, password, and avatar.
const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true
    },
    email: {
      type: String,
      required: true,
      unique: true
    },
    password: {
      type: String,
      required: true
    },
    avatar: {
      type: String,
      default:"https://avatars.githubusercontent.com/u/97174581?v=4"
    },
    easyScore:{
      type: Number,
      default:0
    },
    mediumScore:{
      type: Number,
      default:0
    },
    hardScore:{
      type: Number,
      default:0
    },
    secretKey:{
      type:String,
      default:""
    }
  },
  // Set options for the schema.
  {
    // Set versionKey to false to exclude __v field in response.
    versionKey: false,
    // Set timestamps to true to automatically add createdAt and updatedAt fields.
    timestamps: true,
  }
);

// Create a User model using the userSchema.
const User = mongoose.model("User", userSchema);

// Export the User model.
module.exports = User;