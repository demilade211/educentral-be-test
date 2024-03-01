import express from "express"; 
import cors from "cors";
import http from "http"
const path = require('path'); 
import auth from "./routes/auth" 

const app = express();
const server = http.createServer(app) 

app.use(cors()); 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));//to handle url encoded data 

app.use(express.static("public"))

app.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, '/public/index.html'))
})

app.use('/api/v1',auth); 
  

export default server;