const mongoose = require('mongoose');

require("dotenv").config();

exports.dbConnect = ()=>{
    mongoose.connect(process.env.MONGODB_URL,{
        useNewUrlParser:true,
        useUnifiedTopology:true
    })
    .then(()=>{console.log("db connected successfully")})
    .catch((err)=>{
        console.log("db connection issues");
        console.error(err);
        process.exit(1);
    })
}