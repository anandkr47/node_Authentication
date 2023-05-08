const mongoose=require("mongoose")
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI)
.then(()=>{
    console.log("mongodb connected");
})
.catch((err)=>{
    console.log(err);
    console.log("failed to connect");
})

const LogInSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    }
})
 const collection=new mongoose.model("collection1",LogInSchema)
 module.exports=collection
    
	
