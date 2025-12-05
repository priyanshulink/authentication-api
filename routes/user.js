const express = require("express");
const router = express.Router();

//handler
const {login, signup} = require("../controller/Auth");
const {auth, isStudent, isAdmin} = require("../middlewares/auth");

router.post("/login", login);
router.post("/signup", signup);

//testing protected route
router.get('/test',auth,(req,res)=>{
    res.json({
        success:true,
        message:'welcome to protected router for test',
    })
})
//protected route
router.get("/student",auth, isStudent, (req,res)=>{
    res.json({
        success:true,
        message:'welcome to the protected route for students',
    })
});

router.get("/admin", auth, isAdmin, (req,res)=>{
    res.json({
        success:true,
        message:'welcome to protected route for admin',
    })
})

module.exports = router;