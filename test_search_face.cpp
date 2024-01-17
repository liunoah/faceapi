//
// Created by 390737991@qq.com on 2018/6/3.
//
#include <string>
#include <vector>
#include <debug.h>
#include "object_detection.h"
#include "face_recognizer.h"
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include "config.h"
#include "file_utils.h"
#include <opencv2/opencv.hpp>
#include "httpreq.h"
#include "json/json.h"
#include <string.h>
#include <iostream>
#include <json/json.h>
#include <string>
//#include <QCoreApplication>
//#include <QDir>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <thread>

#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <map>
#include <ctime>

#include <crow.h>
#include "token.h"
// log
#include <spdlog/spdlog.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

//using namespace std;
//using namespace sql; // Add this line to use the sql namespace
//std::string softwareVersion = "1.0.0";
//std::string softwareToken = "1";

// 配置文件
std::string softwareVersion;
std::string softwareToken;
std::string dbHost;
std::string dbUsername;
std::string dbPassword;
int appPort;

// 创建控制台日志记录器
auto console_logger = spdlog::stdout_logger_mt("console");
// 创建文件日志记录器
auto file_logger = spdlog::basic_logger_mt("file", "log.txt");

using namespace std;
using namespace dl;
using namespace vision;
using namespace sql; // Add this line to use the sql namespace

#define message "HTTP server is ready!"//返回给客户机的信息

void test_search_face_video1(string video_file);

// 创建 mysql 链接
sql::mysql::MySQL_Driver *driver;
sql::Connection *con;
sql::Connection *createConnection()
{

    try
    {
        // 创建MySQL连接
        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect(dbHost, dbUsername, dbPassword);

        // 连接成功后的操作
        if (con)
        {
            // std::cout << "Connected to MySQL!" << std::endl;
            return con;
        }
    }
    catch (sql::SQLException &e)
    {
        std::cout << "SQL Exception: " << e.what() << std::endl;
        file_logger->debug("SQL Exception: ", e.what());
    }

    return nullptr;
}

sql::ResultSet *executeQuery(const std::string &sqlQuery)
{
    // sql::Connection *con = createConnection();
    sql::Statement *stmt;
    sql::ResultSet *res;

    if (con)
    {
        try
        {
            file_logger->debug("sql: {}", sqlQuery);
            console_logger->debug("sql: {}", sqlQuery);
            // 创建一个 SQL 语句
            stmt = con->createStatement();
            // 使用 Statement 执行查询
            res = stmt->executeQuery(sqlQuery);

            // delete stmt;
            return res;
        }
        catch (sql::SQLException &e)
        {
            std::cout << "SQL Exception1: " << e.what() << std::endl;
            file_logger->debug("SQL Exception1: ", e.what());
            return nullptr;
        }

        // delete con;
    }

    return nullptr;
}

void deleteConnection(sql::Connection *con)
{
    if (con)
    {
        delete con;
    }
}


int init()
{
    //QDir get_currentDir = QDir::current();
    boost::property_tree::ptree config;

    char buffer[1024];
        if (getcwd(buffer, sizeof(buffer)) != NULL) {
            std::cout << "当前目录：" << buffer << std::endl;
        } else {
            std::cerr << "获取当前目录失败" << std::endl;
            return EXIT_FAILURE;
        }


    try
    {
        strcat(buffer, "/");
        strcat(buffer, "config.ini");
        std::cout << "当前目录 config：" << buffer << std::endl;
        boost::property_tree::ini_parser::read_ini(buffer, config);

        // 读取 [database] 配置项
        dbHost = config.get<std::string>("database.host");
        dbUsername = config.get<std::string>("database.username");
        dbPassword = config.get<std::string>("database.password");

        // 读取 [soft] 配置项
        softwareVersion = config.get<std::string>("soft.softwareVersion");
        softwareToken = config.get<std::string>("soft.softwareToken");
        appPort = config.get<int>("soft.appPort");

        // 读取 [log] 配置项
        std::string logLevel = config.get<std::string>("log.logLevel");
        std::string location = config.get<std::string>("log.location");

        file_logger = spdlog::basic_logger_mt("file1", location);
        if (logLevel == "debug")
        {
            // 设置控制台和文件日志记录器的日志等级
            console_logger->set_level(spdlog::level::debug);
            file_logger->set_level(spdlog::level::debug);
        }
        else if (logLevel == "info")
        {
            console_logger->set_level(spdlog::level::info);
            file_logger->set_level(spdlog::level::info);
        }
        else if (logLevel == "warn")
        {
            console_logger->set_level(spdlog::level::warn);
            file_logger->set_level(spdlog::level::warn);
        }

        // set_log_level(logging::trivial::info);
        // logging::add_file_log("logfile.log"); // 设置日志文件名

        // 输出配置项值
        std::cout << "Database Host: " << dbHost << std::endl;
        std::cout << "Database Username: " << dbUsername << std::endl;
        std::cout << "Database Password: " << dbPassword << std::endl;
        std::cout << "Software Version: " << softwareVersion << std::endl;
        std::cout << "Software Token: " << softwareToken << std::endl;
        std::cout << "Software appPort: " << appPort << std::endl;
        std::cout << "log level: " << logLevel << std::endl;
        // 记录调试信息到文件
        file_logger->debug("Database Host: {}", dbHost);
        file_logger->debug("Database Username: {}", dbUsername);
        file_logger->debug("Database Password: {}", dbPassword);
        file_logger->debug("Software Version: {}", softwareVersion);
        file_logger->debug("Software Token: {}", softwareToken);
        file_logger->debug("Software appPort: {}", appPort);
        file_logger->debug("log level: {}", logLevel);
        console_logger->debug("Database Host: {}", dbHost);
        console_logger->debug("Database Username: {}", dbUsername);
        console_logger->debug("Database Password: {}", dbPassword);
        console_logger->debug("Software Version: {}", softwareVersion);
        console_logger->debug("Software Token: {}", softwareToken);
        console_logger->debug("Software appPort: {}", appPort);
        console_logger->debug("log level: {}", logLevel);
    }
    catch (const boost::property_tree::ptree_error &e)
    {
        std::cerr << "Failed to read config file: " << e.what() << std::endl;
    }

    createConnection();

    return 0;
}

// 处理函数
crow::json::wvalue getVersionHandler()
{
    crow::json::wvalue x;

//    string video_file = "https:?/123423141";
//    thread second(test_search_face_video1, video_file);
//    second.detach();
    x["rescode"] = 1;
    x["version"] = softwareVersion;
    return x;
}

crow::json::wvalue logoutHandler(const crow::request &req)
{
    // 解析请求数据
    auto json = crow::json::load(req.body);

    // 检查是否成功解析JSON数据
    if (!json)
    {
        crow::json::wvalue response_json;
        response_json["rescode"] = 0;
        response_json["msg"] = "Invalid JSON";
        return response_json;
    }

    // 获取token
    std::string token = json["token"].s();

    // print token
    std::cout << "token: " << token << std::endl;

    // 返回json
    crow::json::wvalue response_json;
    bool res = validateToken(token);
    if (res)
    {
        // 校验成功
        invalidateToken(token);

        response_json["rescode"] = 1;
        return response_json;
    }
    else
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
}
// 查询 用户
crow::json::wvalue getUserHandler(const crow::request &req)
{
    // 解析请求数据
    auto json = crow::json::load(req.body);
    // 返回数据
    crow::json::wvalue response_json;
    // 检查是否成功解析JSON数据
    if (!json)
    {
        crow::json::wvalue response_json;
        response_json["rescode"] = 0;
        response_json["msg"] = "Invalid JSON";
        return response_json;
    }
    // console_logger->debug("get user json", json.dump());
    // 获取token
    std::string token = json["token"].s();

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    // 返回json
    std::string name;
    std::string cardId;
    std::string organization;
    std::string type;
    std::string station;
    std::string imgUrl;
    try
    {
        name = json["name"].s();
        cardId = json["cardId"].s();
        organization = json["organization"].s();
        type = json["type"].s();
        station = json["station"].s();
    }
    catch (const std::exception &e)
    {
        // 处理异常的代码
        console_logger->debug("get user Exception in reading parameters: {}", e.what());
        // response_json["rescode"] = 0;
        // response_json["msg"] = "get user Exception in reading parameters";
        // return response_json;
    }

    // 准备 SQL 查询语句
    std::string sqlQuery = "SELECT * FROM user WHERE 1=1";

    // 根据条件拼接SQL查询语句
    if (!name.empty())
        sqlQuery += " AND name = '" + name + "'";
    if (!cardId.empty())
        sqlQuery += " AND cardId = '" + cardId + "'";
    if (!organization.empty())
        sqlQuery += " AND organization = '" + organization + "'";
    if (!type.empty())
        sqlQuery += " AND type = '" + type + "'";
    if (!station.empty())
        sqlQuery += " AND station = '" + station + "'";

    sql::ResultSet *res = executeQuery(sqlQuery);
    if (res->next())
    {

        response_json["user"]["name"] = res->getString("name");
        response_json["user"]["cardId"] = res->getString("cardId");
        response_json["user"]["organization"] = res->getString("organization");
        response_json["user"]["type"] = res->getString("type");
        response_json["user"]["station"] = res->getString("station");
        response_json["user"]["imgUrl"] = res->getString("imgUrl");

        delete res;
        return response_json;
    }
    else
    {
        delete res;
        response_json["rescode"] = 0;
        response_json["msg"] = "No DATA";
        return response_json;
    }
    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    return response_json;
}
// create access source
crow::json::wvalue createAccessSourceHandler(const crow::request &req)
{
    // 解析请求数据
    auto json = crow::json::load(req.body);
    // 返回数据
    crow::json::wvalue response_json;
    // 检查是否成功解析JSON数据
    if (!json)
    {
        crow::json::wvalue response_json;
        response_json["rescode"] = 0;
        response_json["msg"] = "Invalid JSON";
        return response_json;
    }

    // 获取token
    std::string token = json["token"].s();

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    // 返回json
    std::string channelNumber;
    std::string username;
    std::string dataPath;
    std::string address;
    std::string password;
    std::string type;
    std::string connectionMethod;
    try
    {
        channelNumber = json["channelNumber"].s();
        username = json["username"].s();
        dataPath = json["dataPath"].s();
        address = json["address"].s();
        password = json["password"].s();
        type = json["type"].s();
        connectionMethod = json["connectionMethod"].s();
    }
    catch (const std::exception &e)
    {
        // 处理异常的代码
        std::cout << "发生异常：" << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = e.what();
        return response_json;
    };

    std::string sqlQuery = "INSERT INTO accessSource(dataPath, channelNumber, type, address, connectionMethod, username, password) VALUES ('" + dataPath + "', '" + channelNumber + "', '" + type + "', '" + address + "', '" + connectionMethod + "', '" + username + "', '" + password + "');";

    response_json["rescode"] = 1;
    response_json["msg"] = "insert success";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);
        std::cout << "res: " << res << std::endl;
        if (!res)
        {
            std::string prefix = address.substr(0,7);
            if(prefix.compare("rtsp://") == 0 || prefix.compare("rtmp://") == 0){
                response_json["rescode"] = 0;
                response_json["msg"] = "insert fail address must be rtmp or rtsp";
                return response_json;
            }
            response_json["rescode"] = 1;
            response_json["msg"] = "insert success";
            console_logger->debug("insert access source address: {}", address);
            string video_file = address;
            thread second(test_search_face_video1, video_file);
            delete res;
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "insert fail";
            delete res;
        }
    }
    catch (const std::exception &e)
    {
        // 处理异常的代码
        std::cout << "发生异常：" << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = e.what();
    };
    return response_json;
}

// split function
vector<string> split(const string &str, const string &pattern)
{
  char *strc = new char[strlen(str.c_str()) + 1];
  strcpy(strc, str.c_str());
  vector<string> resultVec;
  char *tmpStr = strtok(strc, pattern.c_str());
  while (tmpStr != NULL)
  {
    resultVec.push_back(string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  delete[] strc;
  return resultVec;
}

// get path gps points
vector<string> getGps(string origin, string destination)
{
  vector<string> gps;
  HttpRequest *Http;
  char http_return[4964096] = {0};
  char http_msg[4096] = {0};
  string url = "http://192.168.1.44:28800/face/facerecognition?origin=" + origin + "&destination=" + destination + "&output=json&key=your key";
  strcpy(http_msg, url.c_str());
  if (Http->HttpGet(http_msg, http_return))
  {
    char *resp = strstr(http_return, "\r\n\r\n") + 4;
    if (nullptr != resp)
    {
      string response = resp;
      Json::Reader reader;
      Json::Value rt;
      if (reader.parse(response, rt))
      {
        Json::Value paths_val = rt["route"]["paths"];
        if (paths_val.size() > 0)
        {
          Json::Value polylines_val = paths_val[0]["steps"];
          for (int j = 0; j < polylines_val.size(); j++)
          {
            vector<string> lines = split(polylines_val[j]["polyline"].asString(), ";");
            for (auto lin : lines)
            {
              if (gps.size() > 0)
              {
                if (gps.back() != lin)
                {
                  gps.push_back(lin);
                }
              }
              else
              {
                gps.push_back(lin);
              }
            }
          }
        }
      }
    }
  }
  return gps;
}

unsigned char* base64_encode(const char* str0)
{
    unsigned char* str = (unsigned char*)str0;	//转为unsigned char无符号,移位操作时可以防止错误
    unsigned char base64_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";//也可以用map,这里用数组其实更方便
    long len;				//base64处理后的字符串长度
    long str_len;			//源字符串长度
    long flag;				//用于标识模3后的余数
    unsigned char* res;		//返回的字符串
    str_len = strlen((const char*)str);
    switch (str_len % 3)	//判断模3的余数
    {
    case 0:flag = 0; len = str_len / 3 * 4; break;
    case 1:flag = 1; len = (str_len / 3 + 1) * 4; break;
    case 2:flag = 2; len = (str_len / 3 + 1) * 4; break;
    }
    res = (unsigned char*)malloc(sizeof(unsigned char) * len + 1);
    for (int i = 0, j = 0; j < str_len - flag; j += 3, i += 4)//先处理整除部分
    {
        //注意&运算和位移运算的优先级,是先位移后与或非,括号不对有可能导致错误
        res[i] = base64_map[str[j] >> 2];
        res[i + 1] = base64_map[(str[j] & 0x3) << 4 | str[j + 1] >> 4];
        res[i + 2] = base64_map[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)];
        res[i + 3] = base64_map[str[j + 2] & 0x3f];
    }
    //不满足被三整除时,要矫正
    switch (flag)
    {
    case 0:break;	//满足时直接退出
    case 1:res[len - 4] = base64_map[str[str_len - 1] >> 2];	//只剩一个字符时,右移两位得到高六位
        res[len - 3] = base64_map[(str[str_len - 1] & 0x3) << 4];//获得低二位再右移四位,自动补0
        res[len - 2] = res[len - 1] = '='; break;				//最后两个补=
    case 2:
        res[len - 4] = base64_map[str[str_len - 2] >> 2];				//剩两个字符时,右移两位得高六位
        res[len - 3] = base64_map[(str[str_len - 2] & 0x3) << 4 | str[str_len - 1] >> 4];	//第一个字符低二位和第二个字符高四位
        res[len - 2] = base64_map[(str[str_len - 1] & 0xf) << 2];	//第二个字符低四位,左移两位自动补0
        res[len - 1] = '=';											//最后一个补=
        break;
    }
    res[len] = '\0';	//补上字符串结束标识
    return res;
}

//base64 编码转换表，共64个
static const char base64_encode_table[] = {
    'A','B','C','D','E','F','G','H','I','J',
    'K','L','M','N','O','P','Q','R','S','T',
    'U','V','W','X','Y','Z','a','b','c','d',
    'e','f','g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v','w','x',
    'y','z','0','1','2','3','4','5','6','7',
    '8','9','+','/'
};

//base64 解码表
static const unsigned char base64_decode_table[] = {
    //每行16个
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                //1 - 16
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                //17 - 32
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,              //33 - 48
    52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,      //49 - 64
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,           //65 - 80
    15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,     //81 - 96
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, //97 - 112
    41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0      //113 - 128
};

/**
 * @brief base64_encode     base64编码
 * @param indata            需编码的数据
 * @param inlen             需编码的数据大小
 * @param outdata           编码后输出的数据
 * @param outlen            编码后输出的数据大小
 * @return  int             0：成功    -1：无效参数
 */
int base64_encode(const char *indata, int inlen, char *outdata, int *outlen)
{
    if(indata == NULL || inlen <= 0) {
        return -1;
    }
/*
    //方法一：
    int i, j;
    char ch;
    int add_len = (inlen % 3 == 0 ? 0 : 3 - inlen % 3); //原字符串需补齐的字符个数
    int in_len = inlen + add_len; //源字符串补齐字符后的长度，为3的倍数
    if(outdata != NULL) {
        //编码，长度为调整之后的长度，3字节一组
        for(i=0, j=0; i<in_len; i+=3, j+=4) {
            //将indata第一个字符向右移动2bit（丢弃2bit）
            ch = base64_encode_table[(unsigned char)indata[i] >> 2]; //对应base64转换表的字符
            outdata[j] = ch; //赋值

            //处理最后一组（最后3个字节）的数据
            if(i == in_len - 3 && add_len != 0) {
                if(add_len == 1) {
                    outdata[j + 1] = base64_encode_table[(((unsigned char)indata[i] & 0x03) << 4) | ((unsigned char)indata[i + 1] >> 4)];
                    outdata[j + 2] = base64_encode_table[((unsigned char)indata[i + 1] & 0x0f) << 2];
                    outdata[j + 3] = '=';
                }
                else if(add_len == 2) {
                    outdata[j + 1] = base64_encode_table[((unsigned char)indata[i] & 0x03) << 4];
                    outdata[j + 2] = '=';
                    outdata[j + 3] = '=';
                }
            }
            //处理正常的3字节数据
            else {
                outdata[j + 1] = base64_encode_table[(((unsigned char)indata[i] & 0x03) << 4) | ((unsigned char)indata[i + 1] >> 4)];
                outdata[j + 2] = base64_encode_table[(((unsigned char)indata[i + 1] & 0x0f) << 2) | ((unsigned char)indata[i + 2] >> 6)];
                outdata[j + 3] = base64_encode_table[(unsigned char)indata[i + 2] & 0x3f];
            }
        }
    }
    if(outlen != NULL) {
        *outlen = in_len * 4 / 3; //编码后的长度
    }
*/
    //方法二：
    int i, j;
    unsigned char num = inlen % 3;
    if(outdata != NULL) {
        //编码，3个字节一组，若数据总长度不是3的倍数，则跳过最后的 num 个字节数据
        for(i=0, j=0; i<inlen - num; i+=3, j+=4) {
            outdata[j] = base64_encode_table[(unsigned char)indata[i] >> 2];
            outdata[j + 1] = base64_encode_table[(((unsigned char)indata[i] & 0x03) << 4) | ((unsigned char)indata[i + 1] >> 4)];
            outdata[j + 2] = base64_encode_table[(((unsigned char)indata[i + 1] & 0x0f) << 2) | ((unsigned char)indata[i + 2] >> 6)];
            outdata[j + 3] = base64_encode_table[(unsigned char)indata[i + 2] & 0x3f];
        }
        //继续处理最后的 num 个字节的数据
        if(num == 1) { //余数为1，需补齐两个字节'='
            outdata[j] = base64_encode_table[(unsigned char)indata[inlen - 1] >> 2];
            outdata[j + 1] = base64_encode_table[((unsigned char)indata[inlen - 1] & 0x03) << 4];
            outdata[j + 2] = '=';
            outdata[j + 3] = '=';
        }
        else if(num == 2) { //余数为2，需补齐一个字节'='
            outdata[j] = base64_encode_table[(unsigned char)indata[inlen - 2] >> 2];
            outdata[j + 1] = base64_encode_table[(((unsigned char)indata[inlen - 2] & 0x03) << 4) | ((unsigned char)indata[inlen - 1] >> 4)];
            outdata[j + 2] = base64_encode_table[((unsigned char)indata[inlen - 1] & 0x0f) << 2];
            outdata[j + 3] = '=';
        }
    }
    if(outlen != NULL) {
        *outlen = (inlen + (num == 0 ? 0 : 3 - num)) * 4 / 3; //编码后的长度
    }

    return 0;
}

static std::string base64Decode(const char* Data, int DataByte) {
    //解码表
    const char DecodeTable[] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        62, // '+'
        0, 0, 0,
        63, // '/'
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
        0, 0, 0, 0, 0, 0, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
        0, 0, 0, 0, 0, 0,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
    };
    std::string strDecode;
    int nValue;
    int i = 0;
    while (i < DataByte) {
        if (*Data != '\r' && *Data != '\n') {
            nValue = DecodeTable[*Data++] << 18;
            nValue += DecodeTable[*Data++] << 12;
            strDecode += (nValue & 0x00FF0000) >> 16;
            if (*Data != '=') {
                nValue += DecodeTable[*Data++] << 6;
                strDecode += (nValue & 0x0000FF00) >> 8;
                if (*Data != '=') {
                    nValue += DecodeTable[*Data++];
                    strDecode += nValue & 0x000000FF;
                }
            }
            i += 4;
        }
        else {
            Data++;
            i++;
        }
    }
    return strDecode;
}

int main1111(void)
{
  string origin = "119.508988,32.356766";
  string destination = "119.497028,32.393829";
  vector<string> gps = getGps(origin, destination);
  for (auto lin : gps)
  {
    cout << lin << endl;
  }



  uchar *yuvdata = nullptr;

  long len = 1;

  //if (file != nullptr) {

  //fseek(file, 0, SEEK_END);

  //size = ftell(file);

  //fseek(file, 0, SEEK_SET);

  yuvdata = new uchar[len];


  //读取内存jpg数据转yuv
      // jpeg->yuv420sp
      cv::_InputArray pic_arr(yuvdata,len);
      cv::Mat mat_rgb=cv::imdecode(pic_arr,1);
      cv::Mat mat_rgb2;
      cv::resize(mat_rgb,mat_rgb2,cv::Size(352,288));
      cv::Mat mat_yuv;
      cv::cvtColor(mat_rgb2,mat_yuv,cv::COLOR_BGR2YUV_I420);
      // mat_yuv.data is yuvdata


  return 0;
}

/***
 * 1:N人脸搜索,测试图片文件
 */
void test_search_face_image() {
    // 测试图片数据
    string image_dir = "../data/test_image";
    string output = "../output";
    //初始化人脸识别
    FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                 det_tnnproto,
                                                 rec_tnnmodel,
                                                 rec_tnnproto,
                                                 database,
                                                 embeddingSize,
                                                 alignment,
                                                 num_thread,
                                                 GPU);

    LOGI("Init FaceRecognizer\n");
    // 获得所有图片
    std::vector<string> image_list = get_files_list(image_dir);
    for (const string &image_file:image_list) {
        string basename = get_basename(image_file);
        printf("load image file: %s\n", image_file.c_str());
        // 读取测试图片
        cv::Mat bgr_image = cv::imread(image_file);
        if (bgr_image.empty()) continue;
        // 创建FrameInfo结构体，用于缓存检测和识别等结果
        FrameInfo frameInfo;
        // 进行1:N人脸搜索
        faceReg->detectSearch(bgr_image, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
        // 可视化人脸识别结果
	
        cv::Mat vis_image = dl::vision::FaceRecognizer::visualizeResult("Recognizer", bgr_image, &frameInfo, 0);
        string out_file = path_joint(output, basename);
        LOGI("save image file: %s\n", out_file.c_str());
        printf("save image file: %s\n", out_file.c_str());
        image_save(out_file, vis_image);
    }

    delete faceReg;
    faceReg = nullptr;
    printf("FINISHED.\n");
}

#include <ctime>
#include <chrono>
#include <string>
long long ChangeTimeToTimestamp(std::string &intpu_time)
{
    try
    {
        int year,month,day,hour,minute,second;
        struct tm time_info;
        strptime(intpu_time.c_str(),"%Y-%m-%d  %H:%M:%S",&time_info);
        auto timestamp = std::chrono::system_clock::from_time_t(std::mktime(&time_info));
        auto duration = timestamp.time_since_epoch();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        return milliseconds;
    }
    catch(const std::exception& e)
    {
        throw e;
    }
}

//cv::Mat subImage = mat_rgb(roi).clone();
typedef struct tag_ImageVid
{
    cv::Mat matImg;
    bool bIsWarn;
}ImageVid;
std::vector<ImageVid>  queueImage;

long long getMilliseconds() {
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
}

/***
 * 1:N人脸搜索,测试视频文件
 */
void test_search_face_video1(string video_file) {
    string prevName;
    int iCount = 0;

    //视频文件夹
    //video_file = "rtsp://121.37.68.30:25554/DevAor=32050100001310000107";
    std::cout << "test_search_face_video1 video_file:" << video_file.c_str() << std::endl;
    //初始化人脸识别
    FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                 det_tnnproto,
                                                 rec_tnnmodel,
                                                 rec_tnnproto,
                                                 database,
                                                 embeddingSize,
                                                 alignment,
                                                 num_thread,
                                                 GPU);
    cv::VideoCapture cap;
    bool ret = get_video_capture(video_file, cap);
    cv::Mat frame;
    while (ret) {
        cap >> frame;
        if (frame.empty()) break;
        // 创建FrameInfo结构体，用于缓存检测和识别等结果

        //LOGI("frame is not null\n");

        ImageVid imgVid;
        imgVid.matImg = frame.clone();
        imgVid.bIsWarn = false;


        FrameInfo frameInfo;
        // 进行1:N人脸搜索
        faceReg->detectSearch(frame, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
        cv::Mat out_face;
        for (int i = 0; i < frameInfo.info.size(); i++) {
            auto obj = frameInfo.info.at(i);
            //cv::Rect rect(obj.x1, obj.y1, obj.x2 - obj.x1, obj.y2 - obj.y1);
            //string labels = obj.name + ":" + to_string(obj.similarity).substr(0, 5);
            //draw_rect_text(imgBRG, rect, labels, cv::Scalar(0, 255, 0));
            //draw_points_texts(imgBRG, obj.landmarks, {}, cv::Scalar(0, 255, 0));
            //LOGD("i=%d,bboxe:[%3.5f,%3.5f,%3.5f,%3.5f],%s", i, obj.x1, obj.y1, obj.x2, obj.y2, labels.c_str());

            FrameInfo resultInfo;
            ObjectInfo face_info;
            face_info.x1 = obj.x1;
            face_info.y1 = obj.y1;
            face_info.x2 = obj.x2;
            face_info.y2 = obj.y2;
            face_info.score = obj.score;
            face_info.landmarks = obj.landmarks;
            resultInfo.info.push_back(face_info);
            FaceAlignment* aligner = new FaceAlignment(112, 112, true);

            aligner->crop_faces_alignment(frame, face_info.landmarks, out_face);

            FrameInfo frameInfoAli;
            // 进行1:N人脸搜索
            faceReg->detectSearch(out_face, &frameInfoAli, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
            //for (int i = 0; i < frameInfoAli.info.size(); i++) {
                //auto obj = frameInfoAli.info.at(i);
                //dl::vision::FaceRecognizer::visualizeResult("Recognizer", out_face, &frameInfoAli, "", 30);

                //cv::Mat FaceRecognizer::visualizeResult(string title,
                //                                     cv::Mat &imgBRG,
                //                                     FrameInfo *frameInfo,
                //                                     string className,
                //                                     int waitKey)
                {
                    //printf("xxxxxxxxxxxxxxxxxxxx size:%d\n", frameInfo->info.size());

                    cv::Scalar size1{ 40, 0.5, 0.1, 0 }; // (字体大小, 无效的, 字符间距, 无效的 }

                    //xxtext.setFont(nullptr, &size1, nullptr, 0);

                    cout << " FaceRecognizer visualizeResult1" << endl;
                    char szTime[1024] = {0};
                    for (int i = 0; i < frameInfoAli.info.size(); i++) {
                        auto obj = frameInfoAli.info.at(i);
                        cv::Rect rect(obj.x1, obj.y1, obj.x2 - obj.x1, obj.y2 - obj.y1);
                        string labels = obj.name + ":" + to_string(obj.similarity).substr(0, 5);
                        //draw_rect_text(imgBRG, rect, labels, cv::Scalar(0, 255, 0));

                        cout << " prevName:" << prevName.c_str() << ", iCount:" << iCount << endl;

                        if (string::npos == obj.name.find("unknown"))
                        {
                            if(obj.name == prevName && iCount < 5)
                            {
                                cout << " obj same" << endl;
                                iCount++;
                                continue;
                            }
                            else
                            {
                                prevName = obj.name;
                                iCount = 0;
                            }
                        }

                        if(obj.similarity > 0.4)
                        {
                            //cv::rectangle(imgBRG, rect, cv::Scalar(0, 255, 0), 2);
                            if (labels != "") {
                                if (string::npos == labels.find("unknown"))
                                {
                                    char* plabel = (char*)labels.c_str();
                                    //ToWchar(plabel, w_str);
                                    //xxtext.putText(imgBRG, w_str, cv::Point(rect.x + 5, rect.y - 5), cv::Scalar(0, 255, 0));

                                    imgVid.bIsWarn = true;
                                }
                                else
                                {
                                    string labels1 = "未知人员";
                                    labels1 += ":" + to_string(obj.similarity).substr(0, 5);
                                    char* plabel = (char*)labels1.c_str();
                                    //char* plabel = "未知人员";
                                }

                            }

                            LOGD("i=%d,bboxe:[%3.5f,%3.5f,%3.5f,%3.5f],%s", i, obj.x1, obj.y1, obj.x2, obj.y2, labels.c_str());
                        }

                        cout << " FaceRecognizer visualizeResult2" << endl;
                        if (string::npos == labels.find("unknown"))
                        {
                            struct timeval time_;
                            gettimeofday(&time_, NULL);
                            sprintf(szTime, "_%llu", time_.tv_sec*1000 + time_.tv_usec/1000);
                            //std::cout << time_.tv_sec << std::endl;
                            std::cout << time_.tv_sec*1000 + time_.tv_usec/1000 << std::endl;

                            std::string strOutputPic = "../output/";
                            strOutputPic += obj.name;
                            strOutputPic += szTime;
                            strOutputPic += ".jpg";
                            printf(" strOutputPic:%s\n", strOutputPic.c_str());
                            //cv::imwrite(strOutputPic.c_str(), imgBRG);
                        }

                        string userToken("1");
                        string appToken("1");
                        string strDeviceId = "111";
                        string strDeviceName = "rtsp";

                        time_t now = time(0); //获取当前系统时间
                        //char* dt = ctime(&now); //将时间转换为字符串格式

                        tm* t= localtime(&now);
                        char szBuffer[1024] = {0};
                        sprintf(szBuffer, "%d-%02d-%02d %02d:%02d:%02d\n",
                                t->tm_year + 1900,
                                t->tm_mon + 1,
                                t->tm_mday,
                                t->tm_hour,
                                t->tm_min,
                                t->tm_sec);

                        string strAlarmTime = szBuffer;
                        string strAlarmType = "重要告警";  //暂时写死
                        string strVideoUrl = "";
                       // time_t now = time(0);

                        memset(szBuffer, 0, 1024);
                        sprintf(szBuffer, "%llu", now);
                        string strAlarmId = szBuffer;
                        string strName = obj.name;
                        string strIdCode = strAlarmId;
                        string strLevel = "1";
                        string strReservation1 = "";
                        string strReservation2 = "";

                        //int rows = out_face.rows;
                        //int cols = out_face.cols * out_face.channels();
                        //size_t size = rows * cols * sizeof(uchar);
                        //char outData[1024*1024*5] = {0};
                        //int outLen = 0;
                        //base64_encode((const char*)out_face.data, size, outData, &outLen);
                        //string strImage = outData;

                        std::string strCurDir;
                        char cwd[FILENAME_MAX]; // FILENAME_MAX为最大路径长度常量
                        if(getcwd(cwd, sizeof(cwd)) != NULL){
                                cout << "当前工作目录为：" << cwd << endl;
                        }else{
                                perror("无法获取当前工作目录");
                                return;
                        }

                        strCurDir = "/nginx/files/image";
                        strCurDir += "/";

                        long long curTime = getMilliseconds();
                        memset(szBuffer, 0, 1024);
                        sprintf(szBuffer, "%llu", curTime);
                        strcat(szBuffer, ".jpg");
                        strCurDir += szBuffer;

                        cout << " xxxxxx strCurDir:" << strCurDir.c_str() << endl;

                        //FILE *file; // 定义文件指针变量
                        //file = fopen(strCurDir.c_str(), "wb"); // 以二进制模式打开或新建文件
                        //if (file == NULL) {
                        //     printf("无法打开文件。\n");
                        //     return;
                        //}
                        //unsigned char binaryData[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // 要写入的二进制数据
                        //int dataSize = sizeof(binaryData); // 获取二进制数据大小
                        //fwrite(out_face.data, sizeof(unsigned char), size, file); // 将二进制数据写入文件中
                        //fclose(file); // 关闭文件

                        cv::imwrite(strCurDir.c_str(), out_face);

                        string strType;
                        std::string sqlQuery = "select type from faceInfo where name = '" + obj.name + "';";
                        std::cout << "test_search_face_video 1 query faceInfo sql: " << sqlQuery.c_str() << std::endl;
                        try{
                            sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                            //std::cout << "res: " << res << std::endl;
                            if (!sqlRes) {
                                std::cout << "test_search_face_video 1 sql query success: " << sqlQuery.c_str() << std::endl;

                                //delete sqlRes;
                            } else {
                                //response["rescode"] = 0;
                                //response["msg"] = "insert fail";
                                std::cout << "sql query fail: " << sqlQuery  << ", sqlRes size:" << sqlRes->next() << std::endl;
                                if(sqlRes->next() > 0)
                                {
                                    strType = sqlRes->getString("type");
                                }
                                delete sqlRes;
                            }

                        }catch (const std::exception& e) {
                            // 处理异常的代码
                                std::cout << "sql query 发生异常：" << e.what() << std::endl;
                                //response["rescode"] = 0;
                                //response["msg"] = e.what();
                                //return crow::response(response);
                       };

                        cout << " strType:" << strType.c_str() << endl;
                        if(strType == "黑名单")
                        {
                            strAlarmType = "严重告警";
                        }

                        if(strType == "")
                        {
                            strAlarmType = "重要告警";
                        }

                        if(strType == "白名单")
                        {
                            strAlarmType = "不告警";
                        }

                        sqlQuery = "INSERT INTO alarm (userToken, appToken, deviceId, deviceName, alarmType, alarmTime, videoUrl, alarmId, name, idCode, level, image, reservation1, reservation2) VALUES ('"
                        + userToken + "', '"
                        + appToken + "', '"
                        + strDeviceId + "', '"
                        + strDeviceName + "', '"
                        + strAlarmType + "', '"
                        + strAlarmTime + "', '"
                        + strVideoUrl + "', '"
                        + strAlarmId + "', '"
                        + strName + "', '"
                        + strIdCode + "', '"
                        + strLevel + "', '"
                        //+ strImage + "', '"
                        + strCurDir + "', '"
                        + strReservation1 + "', '"
                        + strReservation2 + "');";

                        std::cout << "test_search_face_video1 sql: " << sqlQuery.c_str() << std::endl;

                        try{
                            sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                            //std::cout << "res: " << res << std::endl;
                            if (!sqlRes) {
                                std::cout << "test_search_face_video1 sql insert success: " << std::endl;
                                //delete sqlRes;
                            } else {
                                delete sqlRes;
                                //response["rescode"] = 0;
                                //response["msg"] = "insert fail";
                                std::cout << "sql insert fail: " << sqlQuery << std::endl;
                            }

                        }catch (const std::exception& e) {
                            // 处理异常的代码
                                std::cout << "sql 发生异常：" << e.what() << std::endl;
                                //response["rescode"] = 0;
                                //response["msg"] = e.what();
                                //return crow::response(response);
                       };

                        /*sqlQuery = "select type from faceInfo where name = '" + obj.name + "';";
                        std::cout << "test_search_face_video1 query faceInfo sql: " << sqlQuery.c_str() << std::endl;
                        try{
                            sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                            //std::cout << "res: " << res << std::endl;
                            if (!sqlRes) {
                                std::cout << "test_search_face_video1 sql query success: " << sqlQuery.c_str() << std::endl;

                                //delete sqlRes;
                            } else {
                                //response["rescode"] = 0;
                                //response["msg"] = "insert fail";
                                std::cout << "sql query fail: " << sqlQuery  << ", sqlRes size:" << sqlRes->next() << std::endl;
                                if(sqlRes->next() > 0)
                                {
                                    string strType = sqlRes->getString("type");
                                }
                                delete sqlRes;
                            }

                        }catch (const std::exception& e) {
                            // 处理异常的代码
                                std::cout << "sql query 发生异常：" << e.what() << std::endl;
                                //response["rescode"] = 0;
                                //response["msg"] = e.what();
                                //return crow::response(response);
                       };*/
                    }

                    cout << " test_search_face_video1 frameInfo" << endl;
                    //cv::imwrite("../result.jpg", imgBRG);
                    //image_show(title, imgBRG, waitKey);
                    //return imgBRG;
                }
            //}
        }

        /*while(queueImage.size() > 400)
        {
            queueImage.erase(queueImage.begin());
        }

        queueImage.push_back(imgVid);

        if(queueImage.size() > 200 && true == queueImage[200].bIsWarn)
        {
            cv::VideoWriter video("output.mp4", cv::VideoWriter::fourcc('M', 'J', 'P', 'G'), 30, cv::Size(640, 480));

            // 循环读取图片，写入输出视频
            for (int i = 0; i < queueImage.size(); i++) {
                cv::Mat frame = queueImage[i].matImg;
                if (frame.empty()) {
                    std::cout << "Error: cannot read image: " << queueImage[i].bIsWarn << std::endl;
                    continue;
                }
                video.write(frame);
            }

            // 释放资源
            video.release();

            auto iter = queueImage.begin();
            while(false == iter->bIsWarn && iter != queueImage.end())
            {
                iter = queueImage.erase(iter);
            }

            if(true == iter->bIsWarn && iter != queueImage.end())
            {
                iter = queueImage.erase(iter);
            }
        }*/

        //cv::imwrite("../result.jpg", out_face);
        // 可视化人脸识别结果
        //dl::vision::FaceRecognizer::visualizeResult("Recognizer", frame, &frameInfo, 30);
    }
    cap.release();
    delete faceReg;
    faceReg = nullptr;
}


/***
 * 1:N人脸搜索,测试视频文件
 */
void test_search_face_video() {

    //视频文件夹
    //string video_file = "rtsp://admin:123456@192.168.1.23:554/Streaming/Channels/101";

    //if(argc < 3){
        //LOG("usage: %s <ip> <port>\n",argv[0]);
        //return;
    //}

    cout << "entery test_search_face_video!" << endl;
    Json::Value root;
    Json::FastWriter fast;
    root["aa"] = Json::Value("11");
    fast.write(root);

    string prevName;
    int iCount = 0;

//    sql::mysql::MySQL_Driver *driver;
//    sql::Connection *con;
//    sql::Statement *stmt;
    //sql::ResultSet *sqlRes;

    /*try
    {
        // 创建MySQL连接
        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect("tcp://23.225.151.200:3306/test", "root", "Admin@123");

        // 连接成功后的操作
        if (con)
        {
             std::cout << "Connected to MySQL! sql 1 2 3" << std::endl;
            // 创建一个 SQL 语句
            stmt = con->createStatement();
            // 使用 Statement 执行查询
            //res = stmt->executeQuery(sqlQuery);
            //delete con;
            //delete stmt;
            //return res;

            cout << "con createStatement!" << endl;
        }
    }
    catch (sql::SQLException &e)
    {
        std::cout << "SQL Exception: " << e.what() << std::endl;
    }*/


    cout << "entery create socket!" << endl;
    //1.创建一个socket套接字
    int local_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (local_fd == -1)
    {
        cout << "socket error!" << endl;
        exit(-1);
    }
    cout << "socket ready!" << endl;

    //2.sockaddr_in结构体：可以存储一套网络地址（包括IP与端口）,此处存储本机IP地址与本地的一个端口
    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(28810);  //绑定6666端口
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); //绑定本机IP地址


    int on = 1;
    setsockopt(local_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    //3.bind()： 将一个网络地址与一个套接字绑定，此处将本地地址绑定到一个套接字上
    int res = bind(local_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (res == -1)
    {
        cout << "bind error!" << endl;
        exit(-1);
    }
    cout << "bind ready!" << endl;

    //4.listen()函数：监听试图连接本机的客户端
    //参数二：监听的进程数
    listen(local_fd, 10);
    cout << "等待来自客户端的连接...." << endl;

    while (true)//循环接收客户端的请求
    {
        //5.创建一个sockaddr_in结构体，用来存储客户机的地址
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        //6.accept()函数：阻塞运行，直到收到某一客户机的连接请求，并返回客户机的描述符
        int client_fd = accept(local_fd, (struct sockaddr *)&client_addr, &len);
        if (client_fd == -1)
        {
            cout << "accept错误\n"
                 << endl;
            exit(-1);
        }

        //7.输出客户机的信息
        char *ip = inet_ntoa(client_addr.sin_addr);
        cout << "客户机： " << ip << " 连接到本服务器成功!" << endl;

        //8.输出客户机请求的信息
        char buff[128*8192*2] = {0};
        int size = 0;
        int currTotalRecvSize = 0;
        int currRecvSize = 0;
        int Cont_len = 0;
        int header = 0;
        int ibody = 0;
        do
        {
            currTotalRecvSize += currRecvSize;
            currRecvSize = read(client_fd, buff+currTotalRecvSize, sizeof(buff)-currTotalRecvSize);

            char *respT = strstr(buff, "\r\n\r\n") + 4;
            if(nullptr != respT)
            {
                header = respT - buff;
                char* pCont = strstr(buff, "Content-Length: ");
                if(nullptr != pCont)
                {
                    Cont_len = atoi(pCont+ strlen("Content-Length: "));
                    //cout << "Cont_len:" << Cont_len << endl;
                }
            }

            //cout << "Request information:"
                 //<< buff+currTotalRecvSize << endl;
            //cout << currRecvSize << " bytes, " << currTotalRecvSize << " currTotalRecvSize" << endl;

            ibody = currTotalRecvSize + currRecvSize - header;
            //cout << "ibody:" << ibody << " bytes" << ", Cont_len:" << Cont_len << endl;
            if(ibody == Cont_len)
            {
                break;
            }
        }while(-1 != currRecvSize || 0 == currRecvSize );

        //size = read(client_fd, buff+size, sizeof(buff)-size);

        cout << "Request size:" << currTotalRecvSize << endl;
        //cout << "Request information1:\n"
             //<< buff+size << endl;
        //cout << size << " bytes1" << endl;

        char *resp = strstr(buff, "\r\n\r\n") + 4;
        if (nullptr != resp)
        {
            //cout << "Request body:\n"
                 //<< resp << endl;
          //string response = resp;
          Json::Reader reader;
          Json::Value rt;
          if (reader.parse(resp, rt))
          {
              cout << "parse succeeded." << endl;
            Json::Value paths_val = rt["originalImage"];
            Json::Value alarmTime_json = rt["alarmTime"];
            Json::Value deviceId = rt["deviceId"];
            Json::Value deviceName = rt["deviceName"];
            Json::Value alarmTime = rt["alarmTime"];

            std::string strAlarmTime = alarmTime_json.asString();
            long long lAlarmTime = ChangeTimeToTimestamp(strAlarmTime);


            cout << "parse succeeded1. paths_val len:" << paths_val.asString().length() << endl;
                //cv::_InputArray pic_arr(paths_val.asString().c_str(), paths_val.asString().length());
                cout << "parse succeeded2. " << endl;
                //cv::Mat mat_rgb=cv::imdecode(pic_arr,1);

                if(0 == paths_val.asString().length())
                {
                    continue;
                }
                    cout << "begin base64Decode" << endl;
                    cv::Mat mat_rgb;
                    std::string s_mat;
                    s_mat = base64Decode(paths_val.asString().data(), paths_val.asString().size());
                    std::vector<char> base64_img(s_mat.begin(), s_mat.end());
                    mat_rgb = cv::imdecode(base64_img, 1);
                    cout << "end base64Decode" << endl;


                    /*****************************************************************************/
                    Json::Value boxInfoArr = rt["bpxInfo"];
                    cout << "xxxxxx boxInfoArr size:" << boxInfoArr.size() << endl;
                    for(int index = 0; index < boxInfoArr.size(); index++)
                    {
                        cv::Rect roi;
                        roi.x = boxInfoArr[index]["leftTopX"].asInt();
                        roi.y = boxInfoArr[index]["leftTopY"].asInt();
                        roi.width = boxInfoArr[index]["rightBottomX"].asInt() - boxInfoArr[index]["leftTopX"].asInt();
                        roi.height = boxInfoArr[index]["rightBottomY"].asInt() - boxInfoArr[index]["leftTopY"].asInt();

                        cout << "roi x:" << roi.x << ", y:" << roi.y << ", width:" << roi.width << ", height:" << roi.height << endl;
                        string strClassName = boxInfoArr[index]["className"].asString();
                        int iClassId = boxInfoArr[index]["classId"].asInt();

                        cv::Mat subImage = mat_rgb(roi).clone();
                        string image_dir = "outalarm";
                        string output = "../output";
                        //初始化人脸识别
                        FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                                     det_tnnproto,
                                                                     rec_tnnmodel,
                                                                     rec_tnnproto,
                                                                     database,
                                                                     embeddingSize,
                                                                     alignment,
                                                                     num_thread,
                                                                     GPU);

                        cout << "Init FaceRecognizer. " << endl;
                        LOGI("Init FaceRecognizer\n");
                        // 获得所有图片

                        // 创建FrameInfo结构体，用于缓存检测和识别等结果
                        FrameInfo frameInfo;
                        // 进行1:N人脸搜索
                        faceReg->detectSearch(subImage, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
                        // 可视化人脸识别结果

                        cout << "Entry visualizeResult. " << endl;
                        cv::Mat vis_image = dl::vision::FaceRecognizer::visualizeResult("Recognizer", subImage, &frameInfo, strClassName, 30);


                        //cv::Mat FaceRecognizer::visualizeResult(string title,
                        //                                     cv::Mat &imgBRG,
                        //                                     FrameInfo *frameInfo,
                        //                                     string className,
                        //                                     int waitKey) {
                            //printf("xxxxxxxxxxxxxxxxxxxx size:%d\n", frameInfo->info.size());
                            cout << " FaceRecognizer visualizeResult1 frameInfo size:" << frameInfo.info.size() << endl;
                            char szTime[1024] = {0};
                            for (int i = 0; i < frameInfo.info.size(); i++) {
                                auto obj = frameInfo.info.at(i);
                                //cv::Rect rect(obj.x1, obj.y1, obj.x2 - obj.x1, obj.y2 - obj.y1);
                                string labels = obj.name + ":" + to_string(obj.similarity).substr(0, 5);
                                //draw_rect_text(imgBRG, rect, labels, cv::Scalar(0, 255, 0));

                                cout << " prevName:" << prevName.c_str() << ", iCount:" << iCount << endl;
                                if (string::npos == obj.name.find("unknown"))
                                {
                                    if(obj.name == prevName && iCount < 5)
                                    {
                                        cout << " obj same" << endl;
                                        iCount++;
                                        continue;
                                    }
                                    else
                                    {
                                        prevName = obj.name;
                                        iCount = 0;
                                    }
                                }

                                if(obj.similarity > 0.4)
                                {
                                    //cv::rectangle(imgBRG, rect, cv::Scalar(0, 255, 0), 2);
                                    if (labels != "") {
                                        //cv::putText(imgBRG,
                                        //            labels,
                                         //           cv::Point(rect.x + 5, rect.y - 5),
                                         //           cv::FONT_HERSHEY_COMPLEX,
                                         //           0.8,
                                         //           cv::Scalar(0, 255, 0), 2);

                                        if (string::npos == labels.find("unknown"))
                                        {
                                            char* plabel = (char*)labels.c_str();
                                            //ToWchar(plabel, w_str);
                                            //xxtext.putText(imgBRG, w_str, cv::Point(rect.x + 5, rect.y - 5), cv::Scalar(0, 255, 0));
                                        }
                                        else
                                        {
                                            string labels1 = "未知人员";
                                            labels1 += ":" + to_string(obj.similarity).substr(0, 5);
                                            char* plabel = (char*)labels1.c_str();
                                            //char* plabel = "未知人员";
                                            //ToWchar(plabel, w_str);
                                            //xxtext.putText(imgBRG, w_str, cv::Point(rect.x + 5, rect.y - 5), cv::Scalar(0, 255, 0));
                                        }

                                    }

                                    //draw_points_texts(imgBRG, obj.landmarks, {}, cv::Scalar(0, 255, 0));
                                    LOGD("i=%d,bboxe:[%3.5f,%3.5f,%3.5f,%3.5f],%s", i, obj.x1, obj.y1, obj.x2, obj.y2, labels.c_str());
                                }
                                else
                                {

                                }

                                string userToken("1");
                                string appToken("1");
                                string strDeviceId = deviceId.asCString();
                                string strDeviceName = deviceName.asCString();
                                string strAlarmTime = alarmTime.asCString();
                                string strAlarmType = "重要告警";  //暂时写死
                                string strVideoUrl = "";
                                time_t now = time(0);
                                char szBuffer[1024] = {0};
                                sprintf(szBuffer, "%llu", now);
                                string strAlarmId = szBuffer;
                                string strName = obj.name;
                                string strIdCode = strAlarmId;
                                string strLevel = "1";
                                string strReservation1 = "";
                                string strReservation2 = "";

                                //int rows = vis_image.rows;
                                //int cols = vis_image.cols * vis_image.channels();
                                //size_t size = rows * cols * sizeof(uchar);
                                //char outData[1024*1024*5] = {0};
                                //int outLen = 0;
                                //base64_encode((const char*)vis_image.data, size, outData, &outLen);
                                //string strImage = outData;

                                std::string strCurDir;
                                char cwd[FILENAME_MAX]; // FILENAME_MAX为最大路径长度常量
                                if(getcwd(cwd, sizeof(cwd)) != NULL){
                                        cout << "当前工作目录为：" << cwd << endl;
                                }else{
                                        perror("无法获取当前工作目录");
                                        return;
                                }

                                strCurDir = "/nginx/files/image";
                                strCurDir += "/";

                                long long curTime = getMilliseconds();
                                memset(szBuffer, 0, 1024);
                                sprintf(szBuffer, "%llu", curTime);
                                strcat(szBuffer, ".jpg");
                                strCurDir += szBuffer;

                                cout << " xxxxxx strCurDir:" << strCurDir.c_str() << endl;

                                cv::imwrite(strCurDir.c_str(), vis_image);

                                string strType;
                                std::string sqlQuery = "select type from faceInfo where name = '" + obj.name + "';";
                                std::cout << "test_search_face_video 1 query faceInfo sql: " << sqlQuery.c_str() << std::endl;
                                try{
                                    sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                                    //std::cout << "res: " << res << std::endl;
                                    if (!sqlRes) {
                                        std::cout << "test_search_face_video 1 sql query success: " << sqlQuery.c_str() << std::endl;

                                        //delete sqlRes;
                                    } else {
                                        //response["rescode"] = 0;
                                        //response["msg"] = "insert fail";
                                        std::cout << "sql query fail: " << sqlQuery  << ", sqlRes size:" << sqlRes->next() << std::endl;
                                        if(sqlRes->next() > 0)
                                        {
                                            strType = sqlRes->getString("type");
                                        }
                                        delete sqlRes;
                                    }

                                }catch (const std::exception& e) {
                                    // 处理异常的代码
                                        std::cout << "sql query 发生异常：" << e.what() << std::endl;
                                        //response["rescode"] = 0;
                                        //response["msg"] = e.what();
                                        //return crow::response(response);
                               };

                                cout << " strType:" << strType.c_str() << endl;
                                if(strType != "白名单" && strClassName == "吸烟")
                                {
                                    strAlarmType = "非白名单,吸烟";
                                }

                                if(strType != "白名单" && strClassName == "不戴安全帽")
                                {
                                    strAlarmType = "非白名单,不戴安全帽";
                                }

                                if(strType != "白名单" && strClassName == "不戴安全帽,吸烟")
                                {
                                    strAlarmType = "非白名单,不戴安全帽,吸烟";
                                }

                                /*if(strType == "")
                                {
                                    strAlarmType = "重要告警";
                                }*/

                                if(strType == "白名单" && strClassName == "吸烟")
                                {
                                    strAlarmType = "吸烟";
                                }

                                if(strType == "白名单" && strClassName == "不戴安全帽")
                                {
                                    strAlarmType = "不戴安全帽";
                                }

                                if(strType == "白名单" && strClassName == "不戴安全帽,吸烟")
                                {
                                    strAlarmType = "不戴安全帽,吸烟";
                                }

                                sqlQuery = "INSERT INTO alarm (userToken, appToken, deviceId, deviceName, alarmType, alarmTime, videoUrl, alarmId, name, idCode, level, image, reservation1, reservation2) VALUES ('"
                                + userToken + "', '"
                                + appToken + "', '"
                                + strDeviceId + "', '"
                                + strDeviceName + "', '"
                                + strAlarmType + "', '"
                                + strAlarmTime + "', '"
                                + strVideoUrl + "', '"
                                + strAlarmId + "', '"
                                + strName + "', '"
                                + strIdCode + "', '"
                                + strLevel + "', '"
                                + strCurDir + "', '"
                                + strReservation1 + "', '"
                                + strReservation2 + "');";

                                std::cout << "sql: " << sqlQuery << std::endl;

                                try{
                                    sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                                    std::cout << "res 1: " << res << std::endl;
                                    if (!sqlRes) {
                                        //response["rescode"] = 1;
                                        //response["msg"] = "insert success";

                                        std::cout << "sql insert success: " << sqlQuery << std::endl;
                                        //delete sqlRes;
                                    } else {
                                        delete sqlRes;
                                        //response["rescode"] = 0;
                                        //response["msg"] = "insert fail";
                                        std::cout << "sql insert fail: " << sqlQuery << std::endl;
                                    }

                                }catch (const std::exception& e) {
                                        // 处理异常的代码
                                        std::cout << "sql 发生异常：" << e.what() << std::endl;
                                        //response["rescode"] = 0;
                                        //response["msg"] = e.what();
                                        //return crow::response(response);
                               };

                                /*sqlQuery = "select type from faceInfo where name = '" + obj.name + "';";
                                std::cout << "test_search_face_video query faceInfo sql: " << sqlQuery.c_str() << std::endl;
                                try{
                                    sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                                    //std::cout << "res: " << res << std::endl;
                                    if (!sqlRes) {
                                        std::cout << "test_search_face_video sql query success: " << sqlQuery.c_str() << std::endl;

                                        //delete sqlRes;
                                    } else {

                                        //response["rescode"] = 0;
                                        //response["msg"] = "insert fail";
                                        std::cout << "sql query fail: " << sqlQuery  << ", sqlRes size:" << sqlRes->next() << std::endl;
                                        if(sqlRes->next() > 0)
                                        {
                                            string strType = sqlRes->getString("type");
                                        }
                                        delete sqlRes;
                                    }

                                }catch (const std::exception& e) {
                                    // 处理异常的代码
                                        std::cout << "sql query 发生异常：" << e.what() << std::endl;
                                        //response["rescode"] = 0;
                                        //response["msg"] = e.what();
                                        //return crow::response(response);
                               };*/
                            }
                        }

                        // 图片路径文件夹
                        //std::string folder_path = "path/to/images";

                        // 读取文件夹中的所有图片
                        /*std::vector<cv::String> filenames;
                        //cv::getFilesInDirectory(folder_path, filenames, false);

                        // 创建VideoWriter对象，设置输出视频参数
                        cv::VideoWriter video("output.mp4", cv::VideoWriter::fourcc('M', 'J', 'P', 'G'), 30, cv::Size(640, 480));

                        // 循环读取图片，写入输出视频
                        for (int i = 0; i < filenames.size(); i++) {
                            cv::Mat frame = cv::imread(filenames[i]);
                            if (frame.empty()) {
                                std::cout << "Error: cannot read image: " << filenames[i] << std::endl;
                                continue;
                            }
                            video.write(frame);
                        }

                        // 释放资源
                        video.release();*/
                    /******************************************************************************/

                    //cv::Rect roi(50,50,200,300);
                    //cv::Mat subImage = mat_rgb(roi).clone();

                //cv::Mat mat_rgb2;
                //cv::resize(mat_rgb,mat_rgb2,cv::Size(352,288));
                //cv::Mat mat_yuv;
                //cv::cvtColor(mat_rgb2,mat_yuv,cv::COLOR_BGR2YUV_I420);

                cout << "parse succeeded3. " << endl;

                // 测试图片数据
                string image_dir = "outalarm";
                string output = "../output";
                //初始化人脸识别
                FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                             det_tnnproto,
                                                             rec_tnnmodel,
                                                             rec_tnnproto,
                                                             database,
                                                             embeddingSize,
                                                             alignment,
                                                             num_thread,
                                                             GPU);

                cout << "Init FaceRecognizer. " << endl;

                LOGI("Init FaceRecognizer\n");
                    // 读取测试图片
                    //cv::Mat bgr_image = cv::imread(image_file);
                    //if (mat_rgb.empty()) continue;
                    // 创建FrameInfo结构体，用于缓存检测和识别等结果
                    FrameInfo frameInfo;
                    // 进行1:N人脸搜索
                    faceReg->detectSearch(mat_rgb, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
                    // 可视化人脸识别结果
                    cout << "Entry visualizeResult 22. " << endl;
                    //cv::Mat vis_image = dl::vision::FaceRecognizer::visualizeResult("Recognizer", mat_rgb, &frameInfo, "", 30);

                    char szTime[1024] = {0};
                    for (int i = 0; i < frameInfo.info.size(); i++) {
                        auto obj = frameInfo.info.at(i);
                        //cv::Rect rect(obj.x1, obj.y1, obj.x2 - obj.x1, obj.y2 - obj.y1);
                        string labels = obj.name + ":" + to_string(obj.similarity).substr(0, 5);
                        //draw_rect_text(imgBRG, rect, labels, cv::Scalar(0, 255, 0));
                        //cv::Mat subImage1 = mat_rgb(rect).clone();

                        cout << " prevName:" << prevName.c_str() << ", iCount:" << iCount << endl;
                        if (string::npos == obj.name.find("unknown"))
                        {
                            if(obj.name == prevName && iCount < 5)
                            {
                                cout << " obj same" << endl;
                                iCount++;
                                continue;
                            }
                            else
                            {
                                prevName = obj.name;
                                iCount = 0;
                            }
                        }

                        if(obj.similarity > 0.4)
                        {
                            //cv::rectangle(imgBRG, rect, cv::Scalar(0, 255, 0), 2);
                            if (labels != "") {
                                if (string::npos == labels.find("unknown"))
                                {
                                    char* plabel = (char*)labels.c_str();
                                }
                                else
                                {
                                    string labels1 = "未知人员";
                                    labels1 += ":" + to_string(obj.similarity).substr(0, 5);
                                    char* plabel = (char*)labels1.c_str();
                                    //char* plabel = "未知人员";
                                }
                            }
                            LOGD("i=%d,bboxe:[%3.5f,%3.5f,%3.5f,%3.5f],%s", i, obj.x1, obj.y1, obj.x2, obj.y2, labels.c_str());
                        }
                        else
                        {

                        }

                        cout << " begin insert sql" << endl;
                        string userToken("1");
                        string appToken("1");
                        string strDeviceId = deviceId.asString();

                        cout << " begin insert deviceId int:" << deviceId.isInt() << ", uint" << deviceId.isUInt() << ", string" << deviceId.isString()<< endl;

                        cout << " begin insert deviceName null:" << deviceName.isNull() << ", uint" << deviceName.isUInt() << ", string" << deviceName.isString() << ",type: " << deviceName.type() << endl;
                        string strDeviceName = deviceName.asString();
                        string strAlarmTime = alarmTime.asString();

                        cout << " begin insert alarmTime int:" << alarmTime.isInt() << ", uint" << alarmTime.isUInt() << ", string" << alarmTime.isString()<< endl;

                        string strAlarmType = "重要告警";  //暂时写死
                        string strVideoUrl = "";
                        time_t now = time(0);
                        char szBuffer[1024] = {0};
                        sprintf(szBuffer, "%llu", now);
                        string strAlarmId = szBuffer;
                        string strName = obj.name;
                        string strIdCode = strAlarmId;
                        string strLevel = "1";
                        string strReservation1 = "";
                        string strReservation2 = "";

                        cout << " begin insert sql2" << endl;

                        //int rows = subImage1.rows;
                        //int cols = subImage1.cols * subImage1.channels();
                        //size_t size = rows * cols * sizeof(uchar);
                        //char outData[1024*1024*5] = {0};
                        //int outLen = 0;

                        cout << " begin insert subImage1 size:" << size << endl;

                        //base64_encode((const char*)subImage1.data, size, outData, &outLen);
                        //string strImage = outData;

                        std::string strCurDir;
                        /*char cwd[FILENAME_MAX]; // FILENAME_MAX为最大路径长度常量
                        if(getcwd(cwd, sizeof(cwd)) != NULL){
                                cout << "当前工作目录为：" << cwd << endl;
                        }else{
                                perror("无法获取当前工作目录");
                                return;
                        }*/

                        strCurDir = "/nginx/files/image";
                        strCurDir += "/";

                        long long curTime = getMilliseconds();
                        memset(szBuffer, 0, 1024);
                        sprintf(szBuffer, "%llu", curTime);
                        strcat(szBuffer, ".jpg");
                        strCurDir += szBuffer;

                        cout << " xxxxxx vis_image strCurDir:" << strCurDir.c_str() << endl;

                        cv::imwrite(strCurDir.c_str(), mat_rgb);

                        cout << " xxxxxx vis_image 22 strCurDir:" << strCurDir.c_str() << endl;
                        string strType;
                        std::string sqlQuery = "select type from faceInfo where name = '" + obj.name + "';";
                        std::cout << "test_search_face_video 1 query faceInfo sql: " << sqlQuery.c_str() << std::endl;
                        try{
                            sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                            //std::cout << "res: " << res << std::endl;
                            if (!sqlRes) {
                                std::cout << "test_search_face_video 1 sql query success: " << sqlQuery.c_str() << std::endl;

                                //delete sqlRes;
                            } else {
                                //response["rescode"] = 0;
                                //response["msg"] = "insert fail";
                                std::cout << "sql query fail: " << sqlQuery  << ", sqlRes size:" << sqlRes->next() << std::endl;
                                if(sqlRes->next() > 0)
                                {
                                    strType = sqlRes->getString("type");
                                }
                                delete sqlRes;
                            }

                        }catch (const std::exception& e) {
                            // 处理异常的代码
                                std::cout << "sql query 发生异常：" << e.what() << std::endl;
                                //response["rescode"] = 0;
                                //response["msg"] = e.what();
                                //return crow::response(response);
                       };

                        cout << " strType:" << strType.c_str() << endl;
                        if(strType == "黑名单")
                        {
                            strAlarmType = "严重告警";
                        }

                        if(strType == "")
                        {
                            strAlarmType = "重要告警";
                        }

                        if(strType == "白名单")
                        {
                            strAlarmType = "不告警";
                        }

                        sqlQuery = "INSERT INTO alarm (userToken, appToken, deviceId, deviceName, alarmType, alarmTime, videoUrl, alarmId, name, idCode, level, image, reservation1, reservation2) VALUES ('"
                        + userToken + "', '"
                        + appToken + "', '"
                        + strDeviceId + "', '"
                        + strDeviceName + "', '"
                        + strAlarmType + "', '"
                        + strAlarmTime + "', '"
                        + strVideoUrl + "', '"
                        + strAlarmId + "', '"
                        + strName + "', '"
                        + strIdCode + "', '"
                        + strLevel + "', '"
                        + strCurDir + "', '"
                        + strReservation1 + "', '"
                        + strReservation2 + "');";

                        std::cout << "sql: " << sqlQuery << std::endl;

                        try{
                            sql::ResultSet *sqlRes = executeQuery(sqlQuery);
                            std::cout << "res 2: " << res << std::endl;
                            if (!sqlRes) {
                                //response["rescode"] = 1;
                                //response["msg"] = "insert success";
                                std::cout << "sql insert success: " << sqlQuery << std::endl;
                                //delete sqlRes;
                            } else {
                                delete sqlRes;
                                //response["rescode"] = 0;
                                //response["msg"] = "insert fail";
                                std::cout << "sql insert fail: " << sqlQuery << std::endl;
                            }

                        }catch (const std::exception& e) {
                                // 处理异常的代码
                                std::cout << "sql 发生异常：" << e.what() << std::endl;
                                //response["rescode"] = 0;
                                //response["msg"] = e.what();
                                //return crow::response(response);
                       };

                    }


                    cout << "Leave visualizeResult. " << endl;

                    //char szName[1024] = {0};
                    //sprintf(szName, "%lld", lAlarmTime);
                    //string out_file = path_joint(output, image_dir);
                    //out_file += "/";
                    //out_file += szName;
                    //out_file += ".jpg";
                    //cout << "path_joint out_file: " << out_file.c_str() << endl;
                    //LOGI("save image file: %s\n", out_file.c_str());
                    //printf("save image file: %s\n", out_file.c_str());
                    //image_save(out_file, vis_image);
                    //}
                    std::string strmessage;
                        strmessage+="HTTP/1.1 200 OK\r\n";                                    //响应行
                        strmessage+="Content-Type:application/json\r\n";                             //响应头
                        strmessage+="server:Tengine \r\n";                                    //响应头
                        strmessage+="name:LiaoKun \r\n";                                      //响应头
                        strmessage+="\r\n";                                                   //空行
                        //strmessage+="<html><head>Hello,World!</head></html>\r\n";
                    //响应体

                    Json::Value outBody;
                    outBody["deviceId"] = deviceId;

                    //int rows = mat_rgb.rows;
                    //int cols = mat_rgb.cols * mat_rgb.channels();
                    //size_t size = rows * cols * sizeof(uchar);
                    //char outData[1024*1024*8] = {0};
                    //int outLen = 0;
                    //base64_encode((const char*)mat_rgb.data, size, outData, &outLen);
                    //outBody["image"] = outData;

                    strmessage += outBody.toStyledString();
                    send(client_fd, strmessage.c_str(), strmessage.length(), 0);
                delete faceReg;
                faceReg = nullptr;
                printf("FINISHED.\n");


          }
          else
          {
              cout << "parse fail." << endl;
          }
        }

        //9.使用第6步accept()返回socket描述符，即客户机的描述符，进行通信。
        //write(client_fd, message, sizeof(message));//返回message

        //10.关闭sockfd
        close(client_fd);
    }

//    delete con;
//    delete stmt;

    close(local_fd);
    
    /*string video_file = "../Face-Recognition-Cpp_bak/data/test-moto-face.mp4";
    //初始化人脸识别
    FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                 det_tnnproto,
                                                 rec_tnnmodel,
                                                 rec_tnnproto,
                                                 database,
                                                 embeddingSize,
                                                 alignment,
                                                 num_thread,
                                                 GPU);
    cv::VideoCapture cap;
    bool ret = get_video_capture(video_file, cap);
    cv::Mat frame;
    while (ret) {
        cap >> frame;
        if (frame.empty()) break;
        // 创建FrameInfo结构体，用于缓存检测和识别等结果
        FrameInfo frameInfo;

	// 进行1:N人脸搜索
        faceReg->detectSearch(frame, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
        // 可视化人脸识别结果
        dl::vision::FaceRecognizer::visualizeResult("Recognizer", frame, &frameInfo, 30);
    }
    cap.release();
    delete faceReg;
    faceReg = nullptr;*/
}

/***
 * 1:N人脸搜索,测试摄像头
 */
void test_search_face_camera() {
    //摄像头ID号(请修改成自己摄像头ID号)
    string video_file = 0;
    //初始化人脸识别
    FaceRecognizer *faceReg = new FaceRecognizer(det_tnnmodel,
                                                 det_tnnproto,
                                                 rec_tnnmodel,
                                                 rec_tnnproto,
                                                 database,
                                                 embeddingSize,
                                                 alignment,
                                                 num_thread,
                                                 GPU);
    cv::VideoCapture cap;
    bool ret = get_video_capture(video_file, cap);
    cv::Mat frame;
    while (ret) {
        cap >> frame;
        if (frame.empty()) break;
        // 创建FrameInfo结构体，用于缓存检测和识别等结果
        FrameInfo frameInfo;
        // 进行1:N人脸搜索
        faceReg->detectSearch(frame, &frameInfo, -1, det_conf_thresh, det_iou_thresh, rec_conf_thresh);
        // 可视化人脸识别结果
        dl::vision::FaceRecognizer::visualizeResult("Recognizer", frame, &frameInfo, "", 30);
    }
    cap.release();
    delete faceReg;
    faceReg = nullptr;

}



int httpReq()
{

    // 初始化 http
       crow::SimpleApp app;
       // 路由

       CROW_ROUTE(app, "/software/version").methods("GET"_method)([]()
                                                                  { return crow::response{getVersionHandler()}; });

       CROW_ROUTE(app, "/user/logout").methods("POST"_method)([](const crow::request &req)
                                                              { return crow::response{logoutHandler(req)}; });

       CROW_ROUTE(app, "/user/login").methods("POST"_method)([](const crow::request &req)
                                                             {
                                                                 // 解析请求数据
                                                                 auto json = crow::json::load(req.body);

                                                                 // 检查是否成功解析JSON数据
                                                                 if (!json)
                                                                 {
                                                                     return crow::response(400, "Invalid JSON");
                                                                 }

                                                                 // 获取用户名和密码
                                                                 std::string username = json["username"].s();
                                                                 std::string password = json["password"].s();

                                                                 // 打印用户名和密码
                                                                 std::cout << "Username: " << username << ", Password: " << password << std::endl;
                                                                 // 执行mysql查询
                                                                 std::string sqlQuery = "SELECT * FROM accessSource WHERE username = '" + username + "' AND password = '" + password + "'";
                                                                 std::cout << "查询username and password sqlQuery: " << sqlQuery << std::endl;
                                                                 sql::ResultSet *res = executeQuery(sqlQuery);

                                                                 // 返回json
                                                                 crow::json::wvalue response_json;
                                                                 if (res->next())
                                                                 {
                                                                     // 校验成功
                                                                     std::string token = generateToken();


                                                                     response_json["rescode"] = 1;
                                                                     response_json["token"] = token;
                                                                     return crow::response(response_json);
                                                                 }
                                                                 else
                                                                 {
                                                                     response_json["rescode"] = 0;
                                                                     response_json["msg"] = "username or password error";
                                                                     return crow::response(response_json);
                                                                 }
                                                                 delete res; });

       // 增加接入源
       CROW_ROUTE(app, "/access/add").methods("POST"_method)([](const crow::request &req)
                                                             { return crow::response{createAccessSourceHandler(req)}; });
       // 根据序号查询接入源 和 查询所有接入源
       CROW_ROUTE(app, "/access/source").methods("POST"_method)([](const crow::request &req)
                                                                {
                                                                    // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                  crow::json::wvalue response;
                                                                   std::string sqlQuery;
                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");


                                                                  // 获取token
                                                                  std::string token = json["token"].s();
                                                                  std::string channelNumber = json["channelNumber"].s();

                                                                  if(validateToken(token)){
                                                                       sqlQuery = "SELECT * FROM accessSource WHERE  channelNumber = '" + channelNumber + "';";
                                                                       std::cout << "access/source: " << sqlQuery << std::endl;

                                                                  }else{

                                                                      response["rescode"] = 0;
                                                                      response["msg"] = "token error";
                                                                      return crow::response(response);
                                                                  }
                                                                  try {
                                                                   sql::ResultSet *res = executeQuery(sqlQuery);
                                                                   if(res->next()){

                                                                           response["accessSource"]["dataPath"] = res->getString("dataPath");
                                                                           response["accessSource"]["channelNumber"] = res->getString("channelNumber");
                                                                           response["accessSource"]["type"] = res->getString("type");
                                                                           response["accessSource"]["address"] = res->getString("address");
                                                                           response["accessSource"]["connectionMethod"] = res->getString("connectionMethod");
                                                                           response["accessSource"]["username"] = res->getString("username");
                                                                           response["accessSource"]["password"] = res->getString("password");


                                                                   }else{
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "channelNumber error";

                                                                       return crow::response(response);
                                                                   }
                                                                   delete res;
                                                                   } catch (const std::exception& e) {
                                                                           std::cout << "发生异常：" << e.what() << std::endl;
                                                                           response["rescode"] = 0;
                                                                           response["msg"] = e.what();
                                                                           return crow::response(response);

                                                                       }


                                                                   response["rescode"] = 1;
                                                                   response["msg"] = "success";
                                                                   return crow::response(response); });

       // 查询人脸底库总量
       CROW_ROUTE(app, "/face/faceSum").methods("POST"_method)([](const crow::request &req)
                                                               {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                  std::string token = json["token"].s();

                                                               if(validateToken(token)){
                                                                   std::string sqlQuery = "SELECT COUNT(*) FROM faceInfo;";
                                                                   std::cout << "sql: " << sqlQuery << std::endl;
                                                                   sql::ResultSet *res = executeQuery(sqlQuery);

                                                                   int count;
                                                                   if (res->next()) {
                                                                       count = res->getInt(1);
                                                                       cout << "查询到的记录数为：" << count << endl;
                                                                       delete res;
                                                                   }

                                                                   std::cout << "count: " << count << std::endl;
                                                                   crow::json::wvalue x({{"rescode", 1}, {"faceSum", count}});
                                                                   return crow::response(x);
                                                               }else{
                                                                   crow::json::wvalue x({{"rescode", 0}, {"msg", "token error"}});
                                                                   return crow::response(x);
                                                               } });
       // 查询人脸底库信息
       CROW_ROUTE(app, "/face").methods("POST"_method)([](const crow::request &req)
                                                       {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                  std::string token = json["token"].s();
                                                                  // 获取身份证
                                                                  std::string idNumber = json["idNumber"].s();

                                                               if (validateToken(token)) {
                                                               std::string sqlQuery = "SELECT * FROM faceInfo WHERE idNumber = '" + idNumber + "';";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);

                                                               if (res->next()) {
                                                                   std::string name = res->getString("name");
                                                                   std::string gender = res->getString("gender");
                                                                   std::string cardid = res->getString("cardid");
                                                                   std::string membership = res->getString("membership");
                                                                   std::string position = res->getString("position");
                                                                   std::string type = res->getString("type");
                                                                   std::string image = res->getString("image");

                                                                   // 在这里使用获取到的人脸信息
                                                                   // 例如，构建一个包含查询结果的 JSON 响应
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 1;
                                                                   response["faceInfo"]["name"] = name;
                                                                   response["faceInfo"]["gender"] = gender;
                                                                   response["faceInfo"]["cardid"] = cardid;
                                                                   response["faceInfo"]["membership"] = membership;
                                                                   response["faceInfo"]["position"] = position;
                                                                   response["faceInfo"]["type"] = type;
                                                                   response["faceInfo"]["image"] = image;

                                                                   delete res;
                                                                   return crow::response(response);
                                                               } else {
                                                                   delete res;
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "No face information found for the provided ID number.";
                                                                   return crow::response(response);
                                                               }
                                                           } else {
                                                               crow::json::wvalue response;
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid token.";
                                                               return crow::response(response);
                                                           } });
       // 推送告警数据
       CROW_ROUTE(app, "/alarm/getAlarmList").methods("POST"_method)([](const crow::request &req)
                                                                     {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                  std::string token = json["token"].s();
                                                                  // 获取身份证
                                                                  std::string alarmId = json["alarmId"].s();

                                                               if (validateToken(token)) {
                                                               std::string sqlQuery = "SELECT * FROM alarm WHERE id = '" + alarmId + "';";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);

                                                               if (res->next()) {
                                                                   std::string alarmType  = res->getString("alarmType");


                                                                   // 在这里使用获取到的人脸信息
                                                                   // 例如，构建一个包含查询结果的 JSON 响应
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 1;
                                                                   response["alarmType "] = alarmType ;


                                                                   delete res;
                                                                   return crow::response(response);
                                                               } else {
                                                                   delete res;
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "No fdata";
                                                                   return crow::response(response);
                                                               }
                                                           } else {
                                                               crow::json::wvalue response;
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid token.";
                                                               return crow::response(response);
                                                           } });

       // 查询报警类型
       CROW_ROUTE(app, "/alarm/alarmType").methods("POST"_method)([](const crow::request &req)
                                                                  {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                  std::string token = json["token"].s();
                                                                  // 获取身份证
                                                                  std::string alarmId = json["alarmId"].s();

                                                               if (validateToken(token)) {
                                                               std::string sqlQuery = "SELECT * FROM alarm WHERE id = '" + alarmId + "';";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);

                                                               if (res->next()) {
                                                                   std::string alarmType  = res->getString("alarmType");


                                                                   // 在这里使用获取到的人脸信息
                                                                   // 例如，构建一个包含查询结果的 JSON 响应
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 1;
                                                                   response["alarmType"] = alarmType ;


                                                                   delete res;
                                                                   return crow::response(response);
                                                               } else {
                                                                   delete res;
                                                                   crow::json::wvalue response;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "No fdata";
                                                                   return crow::response(response);
                                                               }
                                                           } else {
                                                               crow::json::wvalue response;
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid token.";
                                                               return crow::response(response);
                                                           } });

       // 推送报警
       CROW_ROUTE(app, "/video/getAlarmList").methods("POST"_method)([](const crow::request &req)
                                                                     {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   // 定义返回数据
                                                                   crow::json::wvalue response;

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");
                                                                    // 获取token
                                                                  /* std::string token = json["token"].s();
                                                                  if (!validateToken(token)) {
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "Invalid token.";
                                                                       return crow::response(response);
                                                                   } */
                                                                  // 获取信息
                                                                   std::string userToken;
                                                                   std::string appToken;
                                                                   std::string deviceId;
                                                                   std::string deviceName;
                                                                   std::string alarmType;
                                                                   std::string alarmTime;
                                                                   std::string videoUrl;
                                                                   std::string alarmId;
                                                                   std::string name;
                                                                   std::string idCode;
                                                                   std::string level;
                                                                   std::string image;
                                                                   std::string reservation1;
                                                                   std::string reservation2;

                                                                   try {
                                                                       userToken = json["userToken"].s();
                                                                       appToken = json["appToken"].s();
                                                                       deviceId = json["deviceId"].s();
                                                                       deviceName = json["deviceName"].s();
                                                                       alarmType = json["alarmType"].s();
                                                                       alarmTime = json["alarmTime"].s();
                                                                       videoUrl = json["videoUrl"].s();
                                                                       alarmId = json["alarmId"].s();
                                                                       name = json["name"].s();
                                                                       idCode = json["idCode"].s();
                                                                       level = json["level"].s();
                                                                       image = json["image"].s();
                                                                       reservation1 = json["reservation1"].s();
                                                                       reservation2 = json["reservation2"].s();
                                                                   // 在这里继续处理获取到的字段值
                                                                   } catch (const std::exception& e) {
                                                                   // 处理异常的代码
                                                                       std::cout << "发生异常：" << e.what() << std::endl;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = e.what();
                                                                       return crow::response(response);
                                                                   };

                                                               std::string sqlQuery = "INSERT INTO alarm (userToken, appToken, deviceId, deviceName, alarmType, alarmTime, videoUrl, alarmId, name, idCode, level, image, reservation1, reservation2) VALUES ('"
                                                               + userToken + "', '"
                                                               + appToken + "', '"
                                                               + deviceId + "', '"
                                                               + deviceName + "', '"
                                                               + alarmType + "', '"
                                                               + alarmTime + "', '"
                                                               + videoUrl + "', '"
                                                               + alarmId + "', '"
                                                               + name + "', '"
                                                               + idCode + "', '"
                                                               + level + "', '"
                                                               + image + "', '"
                                                               + reservation1 + "', '"
                                                               + reservation2 + "');";

                                                               std::cout << "sql: " << sqlQuery << std::endl;

                                                               try{
                                                                   sql::ResultSet *res = executeQuery(sqlQuery);
                                                                   std::cout << "res: " << res << std::endl;
                                                                   if (!res) {
                                                                   response["rescode"] = 1;
                                                                   response["msg"] = "insert success";
                                                                   delete res;
                                                                   } else {
                                                                       delete res;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "insert fail";
                                                                   }

                                                               }catch (const std::exception& e) {
                                                                   // 处理异常的代码
                                                                       std::cout << "发生异常：" << e.what() << std::endl;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = e.what();
                                                                       return crow::response(response);
                                                                   };




                                                               return crow::response(response); });
       // 1.8查询所有实时告警
       CROW_ROUTE(app, "/alarm/live").methods("POST"_method)([](const crow::request &req)
                                                             {
                                                                 // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   crow::json::wvalue response;
                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                   std::string token = json["token"].s();
                                                                    if (!validateToken(token)){
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "Invalid token.";
                                                                       return crow::response(response);
                                                                    }

                                                                   std::string sqlQuery = "SELECT idCode,deviceName, alarmType, alarmTime FROM alarm;";
                                                                   std::cout << "sql: " << sqlQuery << std::endl;

                                                                   sql::ResultSet *res = executeQuery(sqlQuery);


                                                                   for (int i = 0; res->next(); i++) {
                                                                   response["alarms"][i]["idCode"] = res->getString("idCode");
                                                                   response["alarms"][i]["deviceName"] = res->getString("deviceName");
                                                                   response["alarms"][i]["alarmType"] = res->getString("alarmType");
                                                                   response["alarms"][i]["alarmTime"] = res->getString("alarmTime");
                                                               }

                                                                   delete res;

                                                                   response["rescode"] = 1;
                                                                   response["mes"] = "success";
                                                                   return crow::response(response); });
       // 1.8查询单个告警详细信息
       CROW_ROUTE(app, "/alarm/detail").methods("POST"_method)([](const crow::request &req)
                                                               {
                                                                 // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   crow::json::wvalue response;
                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取token
                                                                   std::string token = json["token"].s();
                                                                   std::string idCode = json["idCode"].s();
                                                                    if (!validateToken(token)){
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "Invalid token.";
                                                                       return crow::response(response);
                                                                    }

                                                                   std::string sqlQuery = "SELECT * FROM alarm WHERE idCode = '" + idCode + "';";
                                                                   std::cout << "sql: " << sqlQuery << std::endl;

                                                                   sql::ResultSet *res = executeQuery(sqlQuery);
                                                                   if(res->next()){
                                                                           try {
                                                                           response["alarm"]["idCode"] = res->getString("idCode");
                                                                           response["alarm"]["appToken"] = res->getString("appToken");
                                                                           response["alarm"]["userToken"] = res->getString("userToken");
                                                                           response["alarm"]["deviceId"] = res->getString("deviceId");
                                                                           response["alarm"]["deviceName"] = res->getString("deviceName");
                                                                           response["alarm"]["alarmType"] = res->getString("alarmType");
                                                                           response["alarm"]["alarmTime"] = res->getString("alarmTime");
                                                                           response["alarm"]["videoUrl"] = res->getString("videoUrl");
                                                                           response["alarm"]["alarmId"] = res->getString("alarmId");
                                                                           response["alarm"]["name"] = res->getString("name");
                                                                           response["alarm"]["level"] = res->getInt("level");
                                                                           response["alarm"]["image"] = res->getInt("image");
                                                                           response["alarm"]["reservation1"] = res->getInt("reservation1");
                                                                           response["alarm"]["reservation2"] = res->getInt("reservation2");
                                                                       } catch (const std::exception& e) {
                                                                           std::cout << "发生异常：" << e.what() << std::endl;
                                                                           response["rescode"] = 0;
                                                                           response["msg"] = e.what();
                                                                           return crow::response(response);
                                                                       }
                                                                   }else{
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = "id code error";
                                                                       return crow::response(response);
                                                                   }
                                                                   delete res;

                                                                   response["rescode"] = 1;
                                                                   response["mes"] = "success";
                                                                   return crow::response(response); });
       // 查询人员
       CROW_ROUTE(app, "/video/getUser").methods("POST"_method)([](const crow::request &req)
                                                                { return crow::response{getUserHandler(req)}; });
       // 增加人员
       CROW_ROUTE(app, "/video/addUser").methods("POST"_method)([](const crow::request &req)
                                                                {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   // 定义返回数据
                                                                   crow::json::wvalue response;

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取信息
                                                                   std::string userToken;
                                                                   std::string appToken;
                                                                   std::string name;
                                                                   std::string cardId;
                                                                   std::string organization;
                                                                   std::string station;
                                                                   std::string imgUrl;
                                                                  try {
                                                                       userToken = json["userToken"].s();
                                                                       appToken = json["appToken"].s();
                                                                       name = json["name"].s();
                                                                       cardId = json["cardId"].s();
                                                                       organization = json["organization"].s();
                                                                       station = json["station"].s();
                                                                       imgUrl = json["imgUrl"].s();

                                                                       // 在这里继续处理获取到的字段值
                                                                   } catch (const std::exception& e) {
                                                                       // 处理异常的代码
                                                                       std::cout << "发生异常：" << e.what() << std::endl;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = e.what();
                                                                       return crow::response(response);
                                                                   };



                                                               if (appToken == softwareToken) {
                                                               std::string sqlQuery = "INSERT INTO user (userToken, appToken, name, cardId, organization, station, imgUrl) VALUES ('" + userToken + "', '" + appToken + "', '" + name + "', '" + cardId + "', '" + organization + "', '" + station + "', '" + imgUrl + "');";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);
                                                               std::cout << "res: " << res << std::endl;

                                                               if (!res) {
                                                                   response["rescode"] = 1;
                                                                   response["msg"] = "insert success";
                                                                   delete res;
                                                               } else {
                                                                   delete res;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "insert fail";
                                                               }
                                                           } else {
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid apptoken.";

                                                           }
                                                           return crow::response(response); });
       // 更新人员信息
       CROW_ROUTE(app, "/video/updateUser").methods("POST"_method)([](const crow::request &req)
                                                                   {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   // 定义返回数据
                                                                   crow::json::wvalue response;

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取信息
                                                                   std::string userToken;
                                                                   std::string appToken;
                                                                   std::string name;
                                                                   std::string cardId;
                                                                   std::string organization;
                                                                   std::string station;
                                                                   std::string imgUrl;
                                                                  try {
                                                                       userToken = json["userToken"].s();
                                                                       appToken = json["appToken"].s();
                                                                       name = json["name"].s();
                                                                       cardId = json["cardId"].s();
                                                                       organization = json["organization"].s();
                                                                       station = json["station"].s();
                                                                       imgUrl = json["imgUrl"].s();

                                                                       // 在这里继续处理获取到的字段值
                                                                   } catch (const std::exception& e) {
                                                                       // 处理异常的代码
                                                                       std::cout << "发生异常：" << e.what() << std::endl;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = e.what();
                                                                       return crow::response(response);
                                                                   };

                                                               if (appToken == softwareToken) {
                                                               std::string sqlQuery = "UPDATE user SET appToken = '" + appToken + "', name = '" + name + "', cardId = '" + cardId + "', organization = '" + organization + "', station = '" + station + "', imgUrl = '" + imgUrl + "' WHERE userToken = '" + userToken + "';";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);
                                                               std::cout << "res: " << res << std::endl;

                                                               if (!res) {
                                                                   response["rescode"] = 1;
                                                                   response["msg"] = "update success";
                                                                   delete res;
                                                               } else {
                                                                   delete res;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "insert fail";
                                                               }
                                                           } else {
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid apptoken.";

                                                           }
                                                           return crow::response(response); });
       // 删除人员信息
       CROW_ROUTE(app, "/video/deleteUser").methods("POST"_method)([](const crow::request &req)
                                                                   {
                                                                   // 解析请求数据
                                                                  auto json = crow::json::load(req.body);
                                                                   // 定义返回数据
                                                                   crow::json::wvalue response;

                                                                  // 检查是否成功解析JSON数据
                                                                  if (!json)
                                                                      return crow::response(400, "Invalid JSON");

                                                                  // 获取信息
                                                                   std::string userToken;
                                                                   std::string appToken;
                                                                   std::string name;
                                                                   std::string cardId;
                                                                  try {
                                                                       userToken = json["userToken"].s();
                                                                       appToken = json["appToken"].s();
                                                                       name = json["name"].s();
                                                                       cardId = json["cardId"].s();

                                                                       // 在这里继续处理获取到的字段值
                                                                   } catch (const std::exception& e) {
                                                                       // 处理异常的代码
                                                                       std::cout << "发生异常：" << e.what() << std::endl;
                                                                       response["rescode"] = 0;
                                                                       response["msg"] = e.what();
                                                                       return crow::response(response);
                                                                   };

                                                               if (appToken == softwareToken) {
                                                               std::string sqlQuery = "DELETE FROM user WHERE userToken = '" + userToken + "' AND appToken = '" + appToken + "' AND name = '" + name + "' AND cardId = '" + cardId + "';";
                                                               std::cout << "sql: " << sqlQuery << std::endl;
                                                               sql::ResultSet *res = executeQuery(sqlQuery);
                                                               std::cout << "res: " << res << std::endl;

                                                               if (!res) {
                                                                   response["rescode"] = 1;
                                                                   response["msg"] = "delete success";
                                                                   delete res;
                                                               } else {
                                                                   delete res;
                                                                   response["rescode"] = 0;
                                                                   response["msg"] = "insert fail";
                                                               }
                                                           } else {
                                                               response["rescode"] = 0;
                                                               response["msg"] = "Invalid apptoken.";

                                                           }
                                                           return crow::response(response); });
       // app.port(appPort).multithreaded().run();

       app.port(appPort);

       // 启用多线程模式并运行应用程序
       app.multithreaded().run();
       // 释放结果集
    cout << "Leave httpReq multithreaded" << endl;
    return 0;
}

int main() {
    // init mysql
    init();
    cout << "Entry main" << endl;
    thread first(httpReq);
    /***测试1:N人脸搜索，需要注册人脸，生成人脸数据库(test_register.cpp)***/

    cout << "Entry test_search_face_video" << endl;

    string video_file = "rtsp://121.37.68.30:25554/DevAor=32050100001310000107";
    thread second(test_search_face_video1, video_file);

    video_file = "rtsp://admin:admin123@192.168.1.54:554/cam/realmonitor?channel=1&subtype=0";
    thread third(test_search_face_video1, video_file);

    //test_search_face_image();  //1:N人脸搜索,测试图片文件
    test_search_face_video();  //1:N人脸搜索,测试视频文件

    //test_search_face_camera();  //1:N人脸搜索,测试摄像头
    first.join();
    return 0;
}
