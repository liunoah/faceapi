CREATE DATABASE IF NOT EXISTS face_database;
USE face_database;

-- 创建接入源表
CREATE TABLE accessSource (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dataPath VARCHAR(255),
    channelNumber VARCHAR(255),
    type VARCHAR(255),
    address VARCHAR(255),
    connectionMethod VARCHAR(255),
    username VARCHAR(255),
    password VARCHAR(255)
);
-- 创建虚拟数据
INSERT INTO accessSource (dataPath, channelNumber, type, address, connectionMethod, username, password)
VALUES
    ('path1', 'channel1', 'type1', 'address1', 'method1', 'user1', 'pass1'),
    ('path2', 'channel2', 'type2', 'address2', 'method2', 'user2', 'pass2'),
    ('path3', 'channel3', 'type3', 'address3', 'method3', 'user3', 'pass3');

-- 创建人脸库表
CREATE TABLE faceInfo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    gender VARCHAR(255),
    cardid VARCHAR(255),
    membership VARCHAR(255),
    position VARCHAR(255),
    idNumber VARCHAR(255),
    type VARCHAR(255),
    image VARCHAR(255000)
);
-- 插入虚拟数据
INSERT INTO faceInfo (name, gender, cardid, membership, position, idNumber, type, image)
VALUES
('张三', '男', '123456', 'VIP会员', '经理', '310************1234', '中国人', 'path/to/image1.jpg'),
('李四', '女', '654321', '普通会员', '职员', '320************5678', '中国人', 'path/to/image2.jpg'),
('王五', '男', '987654', '普通会员', '职员', '330************9012', '中国人', 'path/to/image3.jpg');


CREATE TABLE alarm (
    id INT AUTO_INCREMENT PRIMARY KEY,
    appToken VARCHAR(255),
    userToken VARCHAR(255),
    deviceId VARCHAR(255),
    deviceName VARCHAR(255),
    alarmType VARCHAR(255),
    alarmTime DATETIME,
    videoUrl VARCHAR(255),
    type VARCHAR(255),
    alarmId VARCHAR(255),
    name VARCHAR(255),
    idCode VARCHAR(255),
    level VARCHAR(255),
    image VARCHAR(255),
    reservation1 VARCHAR(255),
    reservation2 VARCHAR(255)
);

-- 插入虚拟数据
INSERT INTO alarm (appToken, userToken, deviceId, deviceName, alarmType, alarmTime, videoUrl, alarmId, name, idCode, level, image, reservation1, reservation2,type)
VALUES
('abc123', 'xyz789', 'device001', 'Device 1', 'Fire Alarm', '2022-01-01 09:00:00', 'https://example.com/video001', 'ALM001', 'John Doe', 'ID123456', "高", NULL, 'Reserve1', 'Reserve2', '白名单'),
('def456', 'uvw456', 'device002', 'Device 2', 'Burglary Alarm', '2022-01-02 14:30:00', 'https://example.com/video002', 'ALM002', 'Jane Smith', 'ID789012', "中", NULL, 'Reserve3', 'Reserve4','临时人员'),
('ghi789', 'mno123', 'device003', 'Device 3', 'Gas Leak Alarm', '2022-01-03 17:45:00', 'https://example.com/video003', 'ALM003', 'David Johnson', 'ID345678', "低", NULL, 'Reserve5', 'Reserve6',"黑名单");
--创建用户表
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    appToken VARCHAR(255),
    userToken VARCHAR(255),
    name VARCHAR(255),
    cardid VARCHAR(255),
    organization VARCHAR(255),
    station VARCHAR(255),
    imgUrl VARCHAR(255),
    type VARCHAR(255),
    username VARCHAR(255),
    password VARCHAR(255)
);
--生成用户虚拟数据
INSERT INTO user (appToken, userToken, name, cardid, organization, station, imgUrl,type,username,password)
VALUES
('abcdefg12345', '987654321abcdefg', 'John Doe', '1234567890', 'ABC Company', 'Manager', 'http://example.com/image1.jpg','admin','admin','admin'),
('hijklm67890', '54321mlkjih', 'Jane Smith', '0987654321', 'XYZ Corporation', 'Engineer', 'http://example.com/image2.jpg','whitelist','user1','pass1'),
('qwerty12345', '54321ytrewq', '张三', '身份证', '人事部', '经理', 'http://example.com/image3.jpg','黑名单','user2','2222');
