const express =require("express")
const speakeasy =require("speakeasy")
const uuid =require("uuid")
const { JsonDB } =require('node-json-db');
const { Config } =require( 'node-json-db/dist/lib/JsonDBConfig');

const app=express();
app.use(express.json())
const PORT=process.env.PORT|| 5000;
app.listen(PORT,()=>{
    console.log(`SERVER STARTED AT ${PORT}`)
})

const db=new JsonDB(new Config("MyDB",true,false,"/"))

app.get("/api",(req,res)=>{
    res.json({
        message:"Welcone to 2FA "
    })
})

//REGISTER USER & create temp secret
app.post("/api/register",(req,res)=>{
    const id=uuid.v4()
    try{
        const path=`/user/${id}`
        const temp_secret=speakeasy.generateSecret()
        db.push(path,{
            id,
            temp_secret
        })
        res.json({
            id,
            secret:temp_secret.base32
        })
    }
    catch(error){
        res.status(500).json({
            status:500,
            message:error,
        })
    }
})

//VERIFY TOKEN AND  MAKE SECRET PERMANENT
app.post("/api/verify",(req,res)=>{
    const {token,userID}=req.body
    console.log({token,userID})
    try{
        const path=`/user/${userID}`
        const user=db.getData(path)
        const {base32:secret}= user.temp_secret
        // Use verify() to check the token against the secret
        const verified = speakeasy.totp.verify({ secret,
            encoding: 'base32',
            token: token });

            if(verified){
                db.push(path,{
                    id:userID,
                    secret:user.temp_secret
                })
                res.json({
                    verified:true
                })
            }
            else{
                res.json({
                    verified:false
                })
            }

    }
    catch(err){
        res.status(500).json({
            status:500,
            message:err,
        })
    }
})


//VALIDATE TOKEN
app.post("/api/validate",(req,res)=>{
    const {token,userID}=req.body
    console.log({token,userID})
    try{
        const path=`/user/${userID}`
        const user=db.getData(path)
        const {base32:secret}= user.secret
        // Use verify() to check the token against the secret
        const tokenValidate = speakeasy.totp.verify({ secret,
            encoding: 'base32',
            token,
            window:1
         });

            if(tokenValidate){
             
                res.json({
                    validate:true
                })
            }
            else{
                res.json({
                    validate:false
                })
            }

    }
    catch(err){
        res.status(500).json({
            status:500,
            message:err,
        })
    }
})