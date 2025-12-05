const express = require('express');
const app = express();

require("dotenv").config();
const PORT = process.env.PORT || 4000;
app.use(express.json());


// cookie-parser middleware: parses cookies on incoming requests
const cookieParser = require('cookie-parser');
app.use(cookieParser());
//db ko import kiya aur connect kiya 
require("./config/database").dbConnect();
//route ko import and mount
const user = require("./routes/user");
app.use("/api/v1",user);

//activate
app.listen(PORT,()=>{
    console.log(`app is listening at ${PORT}`);
})