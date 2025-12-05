const bcrypt = require("bcrypt");
const User = require("../model/User");
const jwt = require("jsonwebtoken");

require("dotenv").config();

//signup route handler
exports.signup = async(req,res)=>{
    try{
        //get data
        const {name,email,password,role}= req.body;
        //check if user already exist
        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"user already exist",
            });
        }

        //secure password
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password,10);// .hash is used to secure password (jise hash karna hai vo value, aur no. of round);
        }
        catch(err){
            res.status(500).json({
                success:false,
                message:"error in hashing password",
            });
        }

        //create entry for user
        const user = await User.create({
            name,email,password:hashedPassword,role
        })
        return res.status(200).json({
            success:true,
            message:"user created successfully"
        });
    }catch(error){
        console.error(error);
        return res.status(500).json({
            success:false,
            message:"user can't be register, please try again latter",
        })
    }
}
exports.login = async(req,res)=>{
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json(
                { 
                    success: false, 
                    message: 'please fill all the entry' 
                });
        }

        const user = await User.findOne({ email }).lean();//.lean() it convert mongodb document into js object
        if (!user) {
            return res.status(401).json({
                 success: false, 
                 message: 'user is not registered' 
                });
         }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).json({
                success: false, 
                message: 'password incorrect' 
            });
        }

        const payload = { email: user.email, id: user._id, role: user.role };

        const token = jwt.sign(payload, process.env.JWT_SECRET || 'secret', { expiresIn: '2h' });

        //user = user.toObject -> to use this instead of .lean() we need to make user let not const.
        user.token = token;
        user.password = undefined;//for sequrity we do undefined 

        const options = { expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), httpOnly: true };

        res.cookie('priyanshu', token, options).status(200).json({ success: true, token, user, message: 'user login successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ success: false, message: 'login fail', details: error.message });
    }
}