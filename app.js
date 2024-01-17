const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();

// 设置存储引擎
const storage = multer.diskStorage({
//   destination: './uploads', // 设置文件保存的目录
  destination: '/nginx/files/image', // 设置文件保存的目录
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const fileExtension = path.extname(file.originalname);
    cb(null, uniqueSuffix + fileExtension); // 生成随机文件名
  }
});

// 创建multer实例
const upload = multer({ storage: storage });

// 处理文件上传的POST请求
app.post('/upload', upload.single('file'), (req, res) => {
  const url = "http://23.225.151.138/files/image/";
  if (!req.file) {
  return res.status(400).send('No file uploaded.');
  }
  
  // 返回URL和文件名
  
  res.send({ data:{url: url, filename: req.file.filename }});
  });

// 启动服务器
app.listen(3000, () => {
  console.log('Server started on port 3000');
});