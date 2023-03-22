require('dotenv').config()
const express = require("express")
const mongoose = require('mongoose')
var cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const cors = require('cors')
const userRoute = require('./routes/userRoute')

const app = express();

const PORT = process.env.PORT || 5000


// middlewares
app.use(express.json())
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser())
app.use(bodyParser.json())
app.use(cors({
    credentials: true,
    origin: "http://localhost:5000",
    optionsSuccessStatus: 200,
}))


// routes
app.use('/api/users', userRoute)


app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})

// connect db 
mongoose.set('strictQuery', false)
mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log(`connect database successed`);
    })
    .catch((error) => {
        console.log(error);
    })
// mongoose.connect(process.env.MONGO_URL)
// const connection = mongoose.connection;

// connection.on('connected', ()=>{
//     console.log("kết nối với mongoodb thành công");
// })

// connection.on("error", ()=>{
//     console.log("kết nối với mongoodb thất bại");
// })


// res.append()
app.get('/example', function (req, res) {
    // Thêm tiêu đề "Content-Type: text/html" vào phản hồi
    res.append('Content-Type', 'text/html');

    // Gửi phản hồi với nội dung là một chuỗi HTML
    res.send('<h1>Hello, World!</h1>');
});

app.get('/set-cookie', function (req, res) {
    // Thiết lập cookie với tên là "username" và giá trị là "john", có thời gian sống là 1 giờ
    res.append('Set-Cookie', 'username=john; Max-Age=3600');

    // Gửi phản hồi
    res.send('Cookie đã được thiết lập');
});

// res.attachment
app.get('/download', function (req, res) {
    const filePath = __dirname + "\package.json";

    // Thiết lập tiêu đề "Content-Disposition" để tải tệp đính kèm
    res.attachment(filePath);

    // Gửi tệp đính kèm
    res.sendFile(filePath);
});


app.get('/token', (req, res) => {
    const token = 'your_access_token';
    res.cookie('accessToken', token, { maxAge: 9000, httpOnly: true });
    res.send('Token has been set');
  });
