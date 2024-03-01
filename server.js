import app from "./app.js";
import dotenv from "dotenv";  
import connectDb from "./db/db.js" 
 

dotenv.config({path: "config/config.env"});

connectDb();
 

const PORT = process.env.PORT || 8000;   



const server = app.listen(PORT, () => {
    console.log(`Server connected on Port: http://localhost:${PORT} in ${process.env.NODE_ENV} MODE`);
});

//Handle unhandled promise rejections
process.on("unhandledRejection",err=>{
    console.log(`ERROR: ${err.message}`);
    console.log(`Shutting down due to unhandled promise rejection`);
    server.close(()=>{
        process.exit(1);
    })
})