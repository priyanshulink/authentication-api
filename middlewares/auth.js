// auth, isStudent, isAdmin

const jwt = require("jsonwebtoken");
require('dotenv').config();

exports.auth = (req,res,next)=>{
    try{
//extract jwt token
console.log("cookies", req.cookies.priyanshu);
console.log("body", req.body.token);
        const token = req.body.token || req.cookies.priyanshu || (req.header("Authorization") ? req.header("Authorization").replace("Bearer ", "") : null);

        if(!token){
            return res.status(401).json({
                success:false,
                message:'Token missing',
            })
        }

        //verify the token 
        try{
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);

            req.user = decode;// this line is improtent for access the role.
        }catch(error){
            return res.status(401).json({
                success:false,
                message:'token is invalid',
            })
        }

        next();

    }catch(error){
        return res.status(401).json({
            success:'false',
            message:'something went wrong while verifying the token',
        })
    }
}

exports.isStudent = (req,res,next)=>{
    try{
      if(req.user.role !== "Student"){
        return res.status(401).json({
            success:false, 
            message:'this is protected route for student'
        })
      }
      next();
    }catch(error){
      return res.status(500).json({
        success:false,
        message:'user role is not matching',
      })
    }
}

exports.isAdmin = (req,res,next)=>{
    try{
      if(req.user.role !== "Admin"){
        return res.status(401).json({
            success:false,
            message:'this is protected route for admin'
        })
      }
      next();
    }catch(error){
      return res.status(500).json({
        success:false,
        message:'user role is not matching',
      })
    }
}