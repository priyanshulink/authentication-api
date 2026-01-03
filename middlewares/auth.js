// auth, isStudent, isAdmin

const jwt = require("jsonwebtoken");
const TokenBlacklist = require("../model/TokenBlacklist");
const { loadKeys } = require("../utils/generateKeys");
require('dotenv').config();

// Load RSA keys for RS256 verification
let publicKey;
try {
    const keys = loadKeys();
    publicKey = keys.publicKey;
} catch (error) {
    console.warn("⚠️  RSA keys not found. Using HS256 verification.");
}

exports.auth = async (req,res,next)=>{
    try{
        //extract jwt token
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success:false,
                message:'No token provided',
            })
        }

        const token = authHeader.split(" ")[1];

        // Check if token is blacklisted
        const blacklisted = await TokenBlacklist.findOne({ token });
        if (blacklisted) {
            return res.status(401).json({
                success: false,
                message: 'Token has been revoked. Please login again.'
            });
        }

        //verify the token 
        try{
            let decoded;
            
            // Try RS256 first if public key is available
            if (publicKey) {
                try {
                    decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
                } catch (rsError) {
                    // Fall back to HS256 if RS256 fails
                    decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
                }
            } else {
                // Use HS256 if no public key
                decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
            }
            
            console.log(decoded);

            req.user = {
                id: decoded.userId,
                role: decoded.role,
                clientId: decoded.clientId || null, // For SSO tokens
                aud: decoded.aud,
                iss: decoded.iss
            };
        }catch(error){
            return res.status(401).json({
                success:false,
                message:'Token expired or invalid',
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