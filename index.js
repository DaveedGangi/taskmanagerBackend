const express=require("express");
const app=express();
app.use(express.json());

const cors=require("cors");
app.use(cors());

const sqlite3=require("sqlite3");
const {open}=require("sqlite");

const path=require("path");


const bcrypt=require("bcrypt");

const jwtToken=require("jsonwebtoken");


require('dotenv').config();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;





let db_path=path.join(__dirname,"dataStorage.db");

let db;


// initialize Database and connection 

const inititalizeDatabaseConnection=async()=>{

    try{
    db= await open({
        filename:db_path,
        driver:sqlite3.Database

    })

    //create a table for users 
    await db.run(`CREATE TABLE IF NOT EXISTS user(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    //create a table for tasks 
    await db.run(`CREATE TABLE IF NOT EXISTS tasks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        due_date DATE,
        status TEXT DEFAULT "pending" CHECK(status IN("pending","in_progress","completed")),
        remarks TEXT,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        created_by INTEGER NOT NULL,
        updated_by INTEGER,

        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES  user(id)

        FOREIGN KEY (created_by) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY (updated_by) REFERENCES user(id) ON DELETE SET NULL

    )`)





    app.listen(PORT,()=>console.log(`Connected Db at port:${PORT}`))
}
catch(error){
    console.log("Error connecting db",error.message);
    process.exit(1);

}



}

inititalizeDatabaseConnection();



// registered user

app.post("/register",async(req,res)=>{

    const{username,password}=req.body;
   

    try{
    const userExist=await db.get("SELECT * FROM user WHERE username=?",[username]);

    if(userExist) return res.status(400).json({message:"User already exits"});

    const hashedPassword=await bcrypt.hash(password,10);

    await db.run("INSERT INTO user (username,password) VALUES(?,?)",[username,hashedPassword]);

    res.status(200).json({message:"User successfully registered"});

    }
    catch(error){
        res.status(500).json({error:error.message});
    }

})

// login user

app.post("/login",async(req,res)=>{
    const{username,password}=req.body;

    try{

    const userExist=await db.get("SELECT * FROM user WHERE username=?",[username]);

    if(!userExist) return res.status(400).json({message:"Invalid user"});

    const checkPassword=await bcrypt.compare(password,userExist.password);

    if(!checkPassword) return res.status(400).json({message:"Invalid password"});

    const payLoad=({
        userId:userExist.id,
        username:userExist.username
    })

    const jwt=jwtToken.sign(payLoad,JWT_SECRET);
    
    return res.send({jwt});

}
catch(error){
    res.status(500).json({error:error.message});
}
    


})

// implementing authentication 

const Auth=async(req,res,next)=>{

    const tokenfind=req.headers.authorization?.split(" ")[1];

    if(!tokenfind) return res.status(400).json({message:"User not eligible"});

    try{
        const findOut=jwtToken.verify(tokenfind,JWT_SECRET);
        if(!findOut){
            return res.status(400).json({message:"User invalid token"})
        }
        req.userId=findOut.userId;
        next();
    }
    catch(error){
        return res.status(401).json({message:"Invalid or expired token"});
    }


}

// app task 

app.post("/task",Auth,async(req,res)=>{

    const{title,description,due_date,status,remarks}=req.body;
    try{

    await db.run("INSERT INTO tasks(title,description,due_date,status,remarks,created_by,user_id) VALUES(?,?,?,?,?,?,?)",[title,description,due_date,status,remarks,req.userId,req.userId]);
   
    res.status(200).json({message:"Task added successfully"});

}
    catch(error){
        res.status(500).json({error:error.message});
    }

})

// get all tasks 

app.get("/task",Auth,async(req,res)=>{

    try{
    const tasks=await db.all("SELECT * FROM tasks");
    return res.status(200).json({tasks});
    }
    catch(error){
        return res.status(500).json({error:error.message});
    }

})

// delte task 
app.delete("/task/:id",Auth,async(req,res)=>{

    const {id}=req.params;
    try{
    await db.run("DELETE FROM tasks WHERE id=?",[id])
    return res.status(200).json({message:"Successfully deleted the task"});
    }
    catch(error){
        return res.status(500).json({error:error.message});

    }

})

// update the task 
app.put("/task/:id",Auth,async(req,res)=>{

    const{id}=req.params;

     const{title,description,due_date,status,remarks}=req.body;

    try{

    const findTask=await db.get("SELECT * FROM tasks WHERE id=?",[id])

    await db.run(`UPDATE tasks 
        SET 
        title=?,description=?,due_date=?,status=?,remarks=?,updated_at=CURRENT_TIMESTAMP,updated_by=?

  
        WHERE id=?`,

    [title,description,due_date,status,remarks,req.userId,id]


    )

    return res.status(200).json({message:"Updated task successfully"});

}
catch(error){
    return res.status(200).json({error:error.message});
}


})

//get the particular task 

app.get("/getTask/:id",Auth,async(req,res)=>{

    const{id}=req.params;

    try{
        const findTask=await db.get("SELECT * FROM tasks WHERE id=?",[id])
        res.status(200).json({task:findTask});
    }
    catch(error){
        res.status(500).json({message:error.message});
    }
})