#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cstdlib> 

#include <iostream>
#include <crow.h>
#include "token.h"
#include <random>

#include <string>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

// log
#include <spdlog/spdlog.h>

using namespace std;
using namespace sql; // Add this line to use the sql namespace
//

#include <fstream>
#include <string.h>
using namespace std;

std::string generateRandomString(int length)
{
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.length() - 1);

    for (int i = 0; i < length; ++i)
    {
        result += charset[distribution(generator)];
    }

    return result;
}
unsigned char *base64_encode(const char *str0)
{
    unsigned char *str = (unsigned char *)str0;                                                      // 转为unsigned char无符号,移位操作时可以防止错误
    unsigned char base64_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // 也可以用map,这里用数组其实更方便
    long len;                                                                                        // base64处理后的字符串长度
    long str_len;                                                                                    // 源字符串长度
    long flag;                                                                                       // 用于标识模3后的余数
    unsigned char *res;                                                                              // 返回的字符串
    str_len = strlen((const char *)str);
    switch (str_len % 3) // 判断模3的余数
    {
    case 0:
        flag = 0;
        len = str_len / 3 * 4;
        break;
    case 1:
        flag = 1;
        len = (str_len / 3 + 1) * 4;
        break;
    case 2:
        flag = 2;
        len = (str_len / 3 + 1) * 4;
        break;
    }
    res = (unsigned char *)malloc(sizeof(unsigned char) * len + 1);
    for (int i = 0, j = 0; j < str_len - flag; j += 3, i += 4) // 先处理整除部分
    {
        // 注意&运算和位移运算的优先级,是先位移后与或非,括号不对有可能导致错误
        res[i] = base64_map[str[j] >> 2];
        res[i + 1] = base64_map[(str[j] & 0x3) << 4 | str[j + 1] >> 4];
        res[i + 2] = base64_map[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)];
        res[i + 3] = base64_map[str[j + 2] & 0x3f];
    }
    // 不满足被三整除时,要矫正
    switch (flag)
    {
    case 0:
        break; // 满足时直接退出
    case 1:
        res[len - 4] = base64_map[str[str_len - 1] >> 2];         // 只剩一个字符时,右移两位得到高六位
        res[len - 3] = base64_map[(str[str_len - 1] & 0x3) << 4]; // 获得低二位再右移四位,自动补0
        res[len - 2] = res[len - 1] = '=';
        break; // 最后两个补=
    case 2:
        res[len - 4] = base64_map[str[str_len - 2] >> 2];                                 // 剩两个字符时,右移两位得高六位
        res[len - 3] = base64_map[(str[str_len - 2] & 0x3) << 4 | str[str_len - 1] >> 4]; // 第一个字符低二位和第二个字符高四位
        res[len - 2] = base64_map[(str[str_len - 1] & 0xf) << 2];                         // 第二个字符低四位,左移两位自动补0
        res[len - 1] = '=';                                                               // 最后一个补=
        break;
    }
    res[len] = '\0'; // 补上字符串结束标识
    return res;
}

int common_shell(const std::string& path, const std::string& name) {
    // 检查路径和名称是否为空
    if (path.empty() || name.empty()) {
        std::cout << "Invalid path or name." << std::endl;
        return -1;
    }
    
    // 构建Shell命令
    std::string command = "curl --location 'http://127.0.0.1:9876/faceadd' \
--header 'Content-Type: application/json' \
--data '{\"path\":\"" + path + "\",\"name\":\"" + name + "\"}'";
    
    // 创建C风格的字符串
    const char* cmd = command.c_str();

    // 调用Shell命令
    int result = system(cmd);

    // 检查命令是否成功执行
    if (WIFEXITED(result) && WEXITSTATUS(result) == 0) {
        // 命令执行成功
        // 进行后续处理
        std::cout << "Command executed successfully." << std::endl;
    } else {
        // 命令执行失败
        // 进行错误处理
        std::cout << "Command execution failed." << std::endl;
    }

    return 0;
}
// base64 编码转换表，共64个
static const char base64_encode_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'};

// base64 解码表
static const unsigned char base64_decode_table[] = {
    // 每行16个
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                // 1 - 16
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                // 17 - 32
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63,              // 33 - 48
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,      // 49 - 64
    0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,           // 65 - 80
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0,     // 81 - 96
    0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 97 - 112
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0      // 113 - 128
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
    if (indata == NULL || inlen <= 0)
    {
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
    // 方法二：
    int i, j;
    unsigned char num = inlen % 3;
    if (outdata != NULL)
    {
        // 编码，3个字节一组，若数据总长度不是3的倍数，则跳过最后的 num 个字节数据
        for (i = 0, j = 0; i < inlen - num; i += 3, j += 4)
        {
            outdata[j] = base64_encode_table[(unsigned char)indata[i] >> 2];
            outdata[j + 1] = base64_encode_table[(((unsigned char)indata[i] & 0x03) << 4) | ((unsigned char)indata[i + 1] >> 4)];
            outdata[j + 2] = base64_encode_table[(((unsigned char)indata[i + 1] & 0x0f) << 2) | ((unsigned char)indata[i + 2] >> 6)];
            outdata[j + 3] = base64_encode_table[(unsigned char)indata[i + 2] & 0x3f];
        }
        // 继续处理最后的 num 个字节的数据
        if (num == 1)
        { // 余数为1，需补齐两个字节'='
            outdata[j] = base64_encode_table[(unsigned char)indata[inlen - 1] >> 2];
            outdata[j + 1] = base64_encode_table[((unsigned char)indata[inlen - 1] & 0x03) << 4];
            outdata[j + 2] = '=';
            outdata[j + 3] = '=';
        }
        else if (num == 2)
        { // 余数为2，需补齐一个字节'='
            outdata[j] = base64_encode_table[(unsigned char)indata[inlen - 2] >> 2];
            outdata[j + 1] = base64_encode_table[(((unsigned char)indata[inlen - 2] & 0x03) << 4) | ((unsigned char)indata[inlen - 1] >> 4)];
            outdata[j + 2] = base64_encode_table[((unsigned char)indata[inlen - 1] & 0x0f) << 2];
            outdata[j + 3] = '=';
        }
    }
    if (outlen != NULL)
    {
        *outlen = (inlen + (num == 0 ? 0 : 3 - num)) * 4 / 3; // 编码后的长度
    }

    return 0;
}

static std::string base64Decode(const char *Data, int DataByte)
{
    // 解码表
    const char DecodeTable[] =
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            62, // '+'
            0, 0, 0,
            63,                                     // '/'
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
    while (i < DataByte)
    {
        if (*Data != '\r' && *Data != '\n')
        {
            nValue = DecodeTable[*Data++] << 18;
            nValue += DecodeTable[*Data++] << 12;
            strDecode += (nValue & 0x00FF0000) >> 16;
            if (*Data != '=')
            {
                nValue += DecodeTable[*Data++] << 6;
                strDecode += (nValue & 0x0000FF00) >> 8;
                if (*Data != '=')
                {
                    nValue += DecodeTable[*Data++];
                    strDecode += nValue & 0x000000FF;
                }
            }
            i += 4;
        }
        else
        {
            Data++;
            i++;
        }
    }
    return strDecode;
}

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
            std::cout << "Connected to MySQL SUCCESS!" << std::endl;
            return con;
        }
    }
    catch (sql::SQLException &e)
    {
        std::cout << "SQL Exception: " << e.what() << std::endl;
        file_logger->debug("SQL Exception: ", e.what());
    }
    std::cout << "Connected to MySQL Fail!" << std::endl;

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
    boost::property_tree::ptree config;

    try
    {
        boost::property_tree::ini_parser::read_ini("config.ini", config);

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
    while (createConnection() == nullptr)
    {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::cerr << "mysql fail" << std::endl;
    }

    return 0;
}

// 处理函数
crow::json::wvalue getVersionHandler()
{
    crow::json::wvalue x;

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
    int page;
    int limit;
    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    try
    {
        page = json["page"].i();
        limit = json["limit"].i();
    }
    catch (const std::exception &e)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    if (limit > 10)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    // 返回json
    std::string name;
    std::string cardid;
    std::string organization;
    std::string type;
    std::string station;
    std::string imgUrl;
    std::string username;
    std::string password;

    std::string sqlCount = "SELECT count(*) as count FROM user  WHERE 1=1";
    std::string sqlQuery = "SELECT * FROM user WHERE 1=1";

    // std::cout << "name字段为空: " << json["name"]  << std::endl;

    if (json.has("name"))
    {
        name = json["name"].s();
        sqlQuery += " AND name = '" + name + "'";
        sqlCount += " AND name = '" + name + "'";
    }
    if (json.has("cardid"))
    {
        cardid = json["cardid"].s();
        sqlQuery += " AND cardid = '" + cardid + "'";
        sqlCount += " AND cardid = '" + cardid + "'";
    }
    if (json.has("organization"))
    {
        organization = json["organization"].s();
        sqlQuery += " AND organization = '" + organization + "'";
        sqlCount += " AND organization = '" + organization + "'";
    }
    if (json.has("type"))
    {
        type = json["type"].s();
        sqlQuery += " AND type = '" + type + "'";
        sqlCount += " AND type = '" + type + "'";
    }
    if (json.has("station"))
    {
        station = json["station"].s();
        sqlQuery += " AND station = '" + station + "'";
        sqlCount += " AND station = '" + station + "'";
    }
    if (json.has("imgUrl"))
    {
        imgUrl = json["imgUrl"].s();
        sqlQuery += " AND imgUrl = '" + imgUrl + "'";
        sqlCount += " AND imgUrl = '" + imgUrl + "'";
    }
    if (json.has("username"))
    {
        username = json["username"].s();
        sqlQuery += " AND username = '" + username + "'";
        sqlCount += " AND username = '" + username + "'";
    }
    if (json.has("password"))
    {
        password = json["password"].s();
        sqlQuery += " AND password = '" + password + "'";
        sqlCount += " AND password = '" + password + "'";
    }

    sql::ResultSet *res1 = executeQuery(sqlCount);
    if (res1)
    {
        while (res1->next())
        {
            response_json["count"] = res1->getInt("count");
        }
        delete res1;
    }
    sqlQuery += " order by id desc ";
    sqlQuery += " LIMIT " + std::to_string((page - 1) * limit) + "," + std::to_string(limit);
    sql::ResultSet *res = executeQuery(sqlQuery);
    for (int i = 0; res->next(); i++)
    {
        response_json["user"][i]["id"] = res->getString("id");
        response_json["user"][i]["appToken"] = res->getString("appToken");
        response_json["user"][i]["userToken"] = res->getString("userToken");
        response_json["user"][i]["name"] = res->getString("name");
        response_json["user"][i]["cardid"] = res->getString("cardid");
        response_json["user"][i]["organization"] = res->getString("organization");
        response_json["user"][i]["type"] = res->getString("type");
        response_json["user"][i]["station"] = res->getString("station");
        response_json["user"][i]["imgUrl"] = res->getString("imgUrl");
        response_json["user"][i]["username"] = res->getString("username");
        response_json["user"][i]["password"] = res->getString("password");
    }
    delete res;

    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    return response_json;
}

// delete 告警
crow::json::wvalue deleteAlarmHandle(const crow::request &req)
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

    int id = json["id"].i();
    std::string sqlQueryCount = "select * from alarm WHERE id = " + std::to_string(id);

    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res->next())
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "data does not exist";
            delete res;
            return response_json;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    sqlQueryCount = "DELETE FROM alarm WHERE id = '" + std::to_string(id) + "'";

    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}

// update 告警
crow::json::wvalue updateAlarmHandle(const crow::request &req)
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

    int id = json["id"].i();
    std::string type = json["type"].s();

    std::string sqlQueryCount = "select * from alarm WHERE id = " + std::to_string(id);

    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res->next())
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "data does not exist";
            delete res;
            return response_json;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    sqlQueryCount = "UPDATE alarm SET alarmType = '" + type + "' WHERE id = " + std::to_string(id);

    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}

// 根据cardid 判断 人脸底库是否存在
bool isFaceInfo(std::string cardid)
{
    std::string sqlQueryCount = "select * from faceInfo WHERE cardid = '" + cardid + "'";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res->next())
        {
            std::cout << "data exist" << std::endl;
            delete res;
            return true;
        }
        else
        {
            std::cout << "data does not exist" << std::endl;
            return false;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "data does not exist" << std::endl;
        return false;
    }
    return false;
}
// 增加人脸底库
crow::json::wvalue addFaceinfoHandle(const crow::request &req)
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

    std::string name;
    std::string gender;
    std::string cardid;
    std::string membership;
    std::string position;
    std::string idNumber;
    std::string type;
    std::string image;
    try
    {
        name = json["name"].s();
        gender = json["gender"].s();
        cardid = json["cardid"].s();
        membership = json["membership"].s();
        position = json["position"].s();
        idNumber = json["idNumber"].s();
        type = json["type"].s();
        image = json["image"].s();
    }
    catch (const std::exception &e)
    {
        // 处理异常的代码
        std::cout << "发生异常：" << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = e.what();
        return response_json;
    };
    if (!isFaceInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data existed";
        return response_json;
    }

    std::string sqlQuery = "INSERT INTO faceInfo (name, gender, cardid, membership, position, idNumber,type,image) VALUES ('" +
                           name + "', '" + gender + "', '" + cardid + "', '" + membership + "', '" + position + "', '" + idNumber + "', '" + type + "', '" + image + "');";

    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }


    std::string url = image;
    size_t slashPos = std::string::npos; // 初始化为无效位置
    int count = 0; // 计数器

    for (size_t i = 0; i < url.length(); i++) {
        if (url[i] == '/') {
            count++;
            if (count == 3) {
                slashPos = i;
                break;
            }
        }
    }

    // 截取从第三个斜杠位置开始的子字符串
    std::string path;
    if (slashPos != std::string::npos) {
        path = url.substr(slashPos);
    }

    std::cout << "剪切出来的路径: " << path << std::endl;
    common_shell("nginx" + path,name);
    return response_json;
}

// 修改人脸库库
crow::json::wvalue updateFaceinfoHandle(const crow::request &req)
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

    std::string name;
    std::string gender;
    std::string cardid;
    std::string membership;
    std::string position;
    std::string idNumber;
    std::string type;
    std::string image;
    try
    {
        name = json["name"].s();
        gender = json["gender"].s();
        cardid = json["cardid"].s();
        membership = json["membership"].s();
        position = json["position"].s();
        idNumber = json["idNumber"].s();
        type = json["type"].s();
        image = json["image"].s();
    }
    catch (const std::exception &e)
    {
        // 处理异常的代码
        std::cout << "发生异常：" << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = e.what();
        return response_json;
    };
    if (isFaceInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data is not existed";
        return response_json;
    }

    std::string sqlQuery = "UPDATE faceInfo SET name = '" +
                           name + "', gender = '" + gender + "', membership = '" + membership + "', position = '" + position + "', idNumber = '" +
                           idNumber + "', type = '" + type + "', image = '" + image + "' WHERE cardid = '" + cardid + "';";

    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete alarm Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}
// 删除人脸底库
crow::json::wvalue deleteFaceHandle(const crow::request &req)
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
    std::string cardid = json["cardid"].s();

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    if (isFaceInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }

    std::string sqlQuery = "DELETE FROM faceInfo WHERE cardid = '" + cardid + "'";

    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete faceInfo Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}

// 查询所有人脸底库
crow::json::wvalue showAllFaceInfoHandler(const crow::request &req)
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
    std::string token = json["token"].s();
    int page;
    int limit;
    // 获取参数

    std::string name;
    std::string cardid;
    std::string membership;
    std::string position;
    std::string type;

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    try
    {
        page = json["page"].i();
        limit = json["limit"].i();
    }
    catch (const std::exception &e)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    if (limit > 10)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    std::string sqlCount = "SELECT count(*) as count FROM faceInfo where 1=1";
    std::string sqlQuery = "SELECT * FROM faceInfo where 1=1";

    if (json.has("name"))
    {
        name = json["name"].s();
        sqlQuery += " AND name = '" + name + "'";
        sqlCount += " AND name = '" + name + "'";
    }
    if (json.has("cardid"))
    {
        cardid = json["cardid"].s();
        sqlQuery += " AND cardid = '" + cardid + "'";
        sqlCount += " AND cardid = '" + cardid + "'";
    }
    if (json.has("membership"))
    {
        membership = json["membership"].s();
        sqlQuery += " AND membership = '" + membership + "'";
        sqlCount += " AND membership = '" + membership + "'";
    }
    if (json.has("position"))
    {
        position = json["position"].s();
        sqlQuery += " AND position = '" + position + "'";
        sqlCount += " AND position = '" + position + "'";
    }
    if (json.has("type"))
    {
        type = json["type"].s();
        sqlQuery += " AND type = '" + type + "'";
        sqlCount += " AND type = '" + type + "'";
    }

    sql::ResultSet *res1 = executeQuery(sqlCount);
    if (res1)
    {
        while (res1->next())
        {
            response_json["count"] = res1->getInt("count");
        }
        delete res1;
    }
    sqlQuery += " order by id desc ";
    sqlQuery += " LIMIT " + std::to_string((page - 1) * limit) + "," + std::to_string(limit);
    sql::ResultSet *res = executeQuery(sqlQuery);
    for (int i = 0; res->next(); i++)
    {
        response_json["face"][i]["id"] = res->getString("id");
        response_json["face"][i]["name"] = res->getString("name");
        response_json["face"][i]["gender"] = res->getString("gender");
        response_json["face"][i]["cardid"] = res->getString("cardid");
        response_json["face"][i]["membership"] = res->getString("membership");
        response_json["face"][i]["position"] = res->getString("position");
        response_json["face"][i]["idNumber"] = res->getString("idNumber");
        response_json["face"][i]["type"] = res->getString("type");
        response_json["face"][i]["image"] = res->getString("image");
    }
    delete res;
    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    return response_json;
}

std::string  frequency = "2";
std::string  threshold = "0.5";
// get threshold，频率
crow::json::wvalue getvalueHandler(const crow::request &req)
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
    // 接受参数
    std::string token;

    // 获取token
    try
    {
        token = json["token"].s();
    }
    catch (const std::exception &e)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    std::cout << "设置阈值" << threshold << std::endl;
    std::cout << "设置设置频率" << frequency << std::endl;

    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    response_json["threshold"] = threshold;
    response_json["frequency"] = frequency;

    return response_json;
}

// 设置阈值 frequency
crow::json::wvalue setvalueHandler(const crow::request &req)
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
    // 接受参数
    std::string token;

    // 获取token
    try
    {
        token = json["token"].s();
        frequency = json["frequency"].s();

        // threshold = std::stof(json["threshold"]);
        threshold = json["threshold"].s();
    }
    catch (const std::exception &e)
    {
        std::cout << "设置设置频率" << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    std::cout << "设置阈值" << threshold << std::endl;
    std::cout << "设置设置频率" << frequency << std::endl;

    response_json["rescode"] = 1;
    response_json["msg"] = "set success";
    response_json["threshold"] = threshold;
    response_json["frequency"] = frequency;
    return response_json;
}
// 查询所有告警
crow::json::wvalue showAllAlarmHandler(const crow::request &req)
{
    // 解析请求数据
    auto json = crow::json::load(req.body);
    // 返回数据
    crow::json::wvalue response_json;

    // 检查是否成功解析JSON数据
    if (!json)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "Invalid JSON";
        return response_json;
    }
    std::string token = json["token"].s();
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }
    int page;
    int limit;
    // 获取信息
    std::string name;
    std::string idCode;
    std::string level;
    std::string deviceName;
    std::string alarmType;
    std::string alarmTime;
    try
    {
        page = json["page"].i();
        limit = json["limit"].i();
    }
    catch (const std::exception &e)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    if (limit > 10)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }

    std::string sqlCount = "SELECT count(*) as count FROM alarm where 1=1";
    std::string sqlQuery = "SELECT * FROM alarm where 1=1";

    if (json.has("name"))
    {
        name = json["name"].s();
        sqlQuery += " AND name = '" + name + "'";
        sqlCount += " AND name = '" + name + "'";
    }
    if (json.has("idCode"))
    {
        idCode = json["idCode"].s();
        sqlQuery += " AND idCode = '" + idCode + "'";
        sqlCount += " AND idCode = '" + idCode + "'";
    }
    if (json.has("level"))
    {
        level = json["level"].s();
        sqlQuery += " AND level = '" + level + "'";
        sqlCount += " AND level = '" + level + "'";
    }
    if (json.has("deviceName"))
    {
        deviceName = json["deviceName"].s();
        sqlQuery += " AND deviceName = '" + deviceName + "'";
        sqlCount += " AND deviceName = '" + deviceName + "'";
    }
    if (json.has("alarmType"))
    {
        alarmType = json["alarmType"].s();
        sqlQuery += " AND alarmType = '" + alarmType + "'";
        sqlCount += " AND alarmType = '" + alarmType + "'";
    }
    if (json.has("alarmTime"))
    {
        alarmTime = json["alarmTime"].s();
        sqlQuery += " AND alarmTime = '" + alarmTime + "'";
        sqlCount += " AND alarmTime = '" + alarmTime + "'";
    }

    sql::ResultSet *res1 = executeQuery(sqlCount);
    if (res1)
    {
        while (res1->next())
        {
            response_json["count"] = res1->getInt("count");
        }
        delete res1;
    }
    sqlQuery += " order by id desc ";
    sqlQuery += " LIMIT " + std::to_string((page - 1) * limit) + "," + std::to_string(limit);
    sql::ResultSet *res = executeQuery(sqlQuery);
    for (int i = 0; res->next(); i++)
    {
        response_json["alarms"][i]["id"] = res->getString("id");
        response_json["alarms"][i]["level"] = res->getString("level");
        response_json["alarms"][i]["idCode"] = res->getString("idCode");
        response_json["alarms"][i]["deviceName"] = res->getString("deviceName");
        response_json["alarms"][i]["alarmType"] = res->getString("alarmType");
        response_json["alarms"][i]["appToken"] = res->getString("appToken");
        response_json["alarms"][i]["alarmTime"] = res->getString("alarmTime");
        response_json["alarms"][i]["userToken"] = res->getString("userToken");
        response_json["alarms"][i]["deviceId"] = res->getString("deviceId");
        response_json["alarms"][i]["videoUrl"] = res->getString("videoUrl");
        response_json["alarms"][i]["alarmId"] = res->getString("alarmId");
        response_json["alarms"][i]["name"] = res->getString("name");
        response_json["alarms"][i]["image"] = res->getString("image");
        response_json["alarms"][i]["reservation1"] = res->getString("reservation1");
        response_json["alarms"][i]["reservation2"] = res->getString("reservation2");
    }
    delete res;
    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    return response_json;
}

// 图片上传处理函数
crow::json::wvalue uploadImageHandler(const crow::request &req)
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
    std::string strBase64;

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    try
    {
        strBase64 = json["strBase64"].s();
        std::string fileName = "/nginx/files/image/" + generateRandomString(16) + ".png";
        string s_mat = base64Decode(strBase64.c_str(), strlen(strBase64.c_str()));
        std::ofstream out_file(fileName);
        response_json["filename"] = fileName;
        out_file << s_mat.c_str();
        out_file.close();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }

    response_json["rescode"] = 1;
    response_json["msg"] = "upload success";
    return response_json;
}
// 查看user是否存在
bool isUserInfo(std::string cardid)
{
    std::string sqlQueryCount = "select * from user WHERE cardid = '" + cardid + "'";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res->next())
        {
            std::cout << "data exist" << std::endl;
            delete res;
            return true;
        }
        else
        {
            std::cout << "data does not exist" << std::endl;
            return false;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "data does not exist" << std::endl;
        return false;
    }
    return false;
}
// 删除用户
crow::json::wvalue deleteUserHandle(const crow::request &req)
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
    std::string cardid = json["cardid"].s();

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    if (isUserInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    std::string sqlQuery = "DELETE FROM user WHERE cardid = '" + cardid + "';";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete faceInfo Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}

// 增加用户
crow::json::wvalue addUserHandle(const crow::request &req)
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
    std::string token = json["token"].s();
    std::string userToken;
    std::string appToken;
    std::string name;
    std::string cardid;
    std::string organization;
    std::string station;
    std::string imgUrl;
    std::string username;
    std::string password;
    std::string type;
    // 获取token
    try
    {
        cardid = json["cardid"].s();
        userToken = json["userToken"].s();
        appToken = json["appToken"].s();
        name = json["name"].s();
        cardid = json["cardid"].s();
        organization = json["organization"].s();
        station = json["station"].s();
        imgUrl = json["imgUrl"].s();
        username = json["username"].s();
        password = json["password"].s();
        type = json["type"].s();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    if (!isUserInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data  exist";
        return response_json;
    }
    std::string sqlQuery = "INSERT INTO user (userToken, appToken, name, cardid, organization, station, imgUrl, username, password,type) VALUES ('" +
                           userToken + "', '" + appToken + "', '" + name + "', '" + cardid + "', '" + organization + "', '" + station + "', '" +
                           imgUrl + "', '" + username + "', '" + password + "', '" + type + "');";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "update user Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data error";
    }

    return response_json;
}
// 更新用户
crow::json::wvalue updateUserHandle(const crow::request &req)
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
    std::string token = json["token"].s();
    std::string userToken;
    std::string appToken;
    std::string name;
    std::string cardid;
    std::string organization;
    std::string station;
    std::string imgUrl;
    std::string username;
    std::string password;
    std::string type;

    // 获取token
    try
    {
        cardid = json["cardid"].s();
        userToken = json["userToken"].s();
        appToken = json["appToken"].s();
        name = json["name"].s();
        cardid = json["cardid"].s();
        organization = json["organization"].s();
        station = json["station"].s();
        imgUrl = json["imgUrl"].s();
        username = json["username"].s();
        password = json["password"].s();
        type = json["type"].s();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    if (isUserInfo(cardid = cardid))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    std::string sqlQuery = "UPDATE user SET appToken = '" + appToken + "', username = '" + username + "', password = '" + password +
                           "', name = '" + name + "', organization = '" + organization + "', userToken = '" + userToken + "', type = '" + type +
                           "', station = '" + station + "', imgUrl = '" + imgUrl + "' WHERE cardid = '" + cardid + "';";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "update user Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data error";
    }

    return response_json;
}

// 查询接入源是否存在
bool isAccessSourceByAddress(std::string address)
{
    std::string sqlQueryCount = "select * from accessSource WHERE address = '" + address + "'";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQueryCount);

        if (!res->next())
        {
            std::cout << "data exist" << std::endl;
            delete res;
            return true;
        }
        else
        {
            std::cout << "data does not exist" << std::endl;
            return false;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "data does not exist" << std::endl;
        return false;
    }
    return false;
}

// 更新接入源
crow::json::wvalue updateAccessHandle(const crow::request &req)
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
    std::string token;
    std::string dataPath;
    std::string channelNumber;
    std::string type;
    std::string address;
    std::string connectionMethod;
    std::string username;
    std::string password;
    try
    {
        token = json["token"].s();
        dataPath = json["dataPath"].s();
        channelNumber = json["channelNumber"].s();
        type = json["type"].s();
        address = json["address"].s();
        connectionMethod = json["connectionMethod"].s();
        username = json["username"].s();
        password = json["password"].s();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    if (isAccessSourceByAddress(address = address))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    std::string sqlQuery = "UPDATE accessSource SET dataPath = '" + dataPath + "', username = '" + username + "', password = '" + password +
                           "', channelNumber = '" + channelNumber + "', type = '" + type + "', address = '" + address +
                           "', connectionMethod = '" + connectionMethod + "' WHERE address = '" + address + "';";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "update user Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data error";
    }

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
            response_json["rescode"] = 1;
            response_json["msg"] = "insert success";
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

// 删除接入源
crow::json::wvalue deleteAccessHandle(const crow::request &req)
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
    std::string token;
    std::string address;

    try
    {
        token = json["token"].s();
        address = json["address"].s();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    if (isAccessSourceByAddress(address = address))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
        return response_json;
    }
    std::string sqlQuery = "DELETE FROM accessSource WHERE address = '" + address + "';";
    try
    {
        sql::ResultSet *res = executeQuery(sqlQuery);

        if (!res)
        {
            response_json["rescode"] = 1;
            response_json["msg"] = "success";
        }
        else
        {
            response_json["rescode"] = 0;
            response_json["msg"] = "fail";
        }

        delete res;
    }
    catch (const std::exception &e)
    {
        std::cout << "delete faceInfo Exception: " << e.what() << std::endl;
        response_json["rescode"] = 0;
        response_json["msg"] = "data does not exist";
    }

    return response_json;
}
// 查询所有接入源
crow::json::wvalue showAllAccessSourceHandler(const crow::request &req)
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
    std::string token = json["token"].s();
    int page;
    int limit;
    // 查询参数
    std::string username;
    std::string channelNumber;
    std::string type;
    std::string address;

    // print token
    std::cout << "token: " << token << std::endl;
    if (!validateToken(token))
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "token error";
        return response_json;
    }

    try
    {
        token = json["token"].s();
        page = json["page"].i();
        limit = json["limit"].i();
    }
    catch (const std::exception &e)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    if (limit > 10)
    {
        response_json["rescode"] = 0;
        response_json["msg"] = "参数错误";
        return response_json;
    }
    std::string sqlCount = "SELECT count(*) as count FROM accessSource where 1=1";
    std::string sqlQuery = "SELECT * FROM accessSource where 1=1";

    if (json.has("username"))
    {
        username = json["username"].s();
        sqlQuery += " AND username = '" + username + "'";
        sqlCount += " AND username = '" + username + "'";
    }
    if (json.has("channelNumber"))
    {
        channelNumber = json["channelNumber"].s();
        sqlQuery += " AND channelNumber = '" + channelNumber + "'";
        sqlCount += " AND channelNumber = '" + channelNumber + "'";
    }
    if (json.has("type"))
    {
        type = json["type"].s();
        sqlQuery += " AND type = '" + type + "'";
        sqlCount += " AND type = '" + type + "'";
    }
    if (json.has("address"))
    {
        address = json["address"].s();
        sqlQuery += " AND address = '" + address + "'";
        sqlCount += " AND address = '" + address + "'";
    }
    sql::ResultSet *res1 = executeQuery(sqlCount);
    if (res1)
    {
        while (res1->next())
        {
            response_json["count"] = res1->getInt("count");
        }
        delete res1;
    }
    sqlQuery += " order by id desc ";
    sqlQuery += " LIMIT " + std::to_string((page - 1) * limit) + "," + std::to_string(limit);
    sql::ResultSet *res = executeQuery(sqlQuery);
    for (int i = 0; res->next(); i++)
    {
        response_json["accessSource"][i]["id"] = res->getString("id");
        response_json["accessSource"][i]["dataPath"] = res->getString("dataPath");
        response_json["accessSource"][i]["channelNumber"] = res->getString("channelNumber");
        response_json["accessSource"][i]["type"] = res->getString("type");
        response_json["accessSource"][i]["address"] = res->getString("address");
        response_json["accessSource"][i]["connectionMethod"] = res->getString("connectionMethod");
        response_json["accessSource"][i]["username"] = res->getString("username");
        response_json["accessSource"][i]["password"] = res->getString("password");
    }
    delete res;
    response_json["rescode"] = 1;
    response_json["msg"] = "success";
    return response_json;
}

int main()
{
    // 初始化
    init();

    // 初始化 http
    crow::SimpleApp app;
    // 路由
    // upload img
    CROW_ROUTE(app, "/upload").methods("POST"_method)([](const crow::request &req)
                                                      { return crow::response{uploadImageHandler(req)}; });
    // 获取阈值和频率
    CROW_ROUTE(app, "/software/getinfo").methods("POST"_method)([](const crow::request &req)
                                                                { return crow::response{getvalueHandler(req)}; });

    // Set threshold
    CROW_ROUTE(app, "/software/setinfo").methods("POST"_method)([](const crow::request &req)
                                                                { return crow::response{setvalueHandler(req)}; });

    // update faceinfo
    CROW_ROUTE(app, "/face/update").methods("POST"_method)([](const crow::request &req)
                                                           { return crow::response{updateFaceinfoHandle(req)}; });
    // delete faceinfo
    CROW_ROUTE(app, "/face/delete").methods("POST"_method)([](const crow::request &req)
                                                           { return crow::response{deleteFaceHandle(req)}; });

    // Search all faceinfo
    CROW_ROUTE(app, "/face/all").methods("POST"_method)([](const crow::request &req)
                                                        { return crow::response{showAllFaceInfoHandler(req)}; });

    // add faceinfo
    CROW_ROUTE(app, "/face/add").methods("POST"_method)([](const crow::request &req)
                                                        { return crow::response{addFaceinfoHandle(req)}; });

    // update alarm
    CROW_ROUTE(app, "/alarm/update").methods("POST"_method)([](const crow::request &req)
                                                            { return crow::response{updateAlarmHandle(req)}; });
    // delete alarm
    CROW_ROUTE(app, "/alarm/delete").methods("POST"_method)([](const crow::request &req)
                                                            { return crow::response{deleteAlarmHandle(req)}; });
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
                                                              std::string sqlQuery = "SELECT * FROM user WHERE username = '" + username + "' AND password = '" + password + "'";
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

    // 查询所有接入源
    CROW_ROUTE(app, "/access").methods("POST"_method)([](const crow::request &req)
                                                      { return crow::response{showAllAccessSourceHandler(req)}; });
    // 删除接入源
    CROW_ROUTE(app, "/access").methods("DELETE"_method)([](const crow::request &req)
                                                        { return crow::response{deleteAccessHandle(req)}; });

    // 更新接入源
    CROW_ROUTE(app, "/access").methods("PUT"_method)([](const crow::request &req)
                                                     { return crow::response{updateAccessHandle(req)}; });

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
    // 查询
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
    CROW_ROUTE(app, "/video/add").methods("POST"_method)([](const crow::request &req)
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
                                                          { return crow::response{showAllAlarmHandler(req)}; });
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
                                                             { return crow::response{addUserHandle(req)}; });

    // 更新人员信息
    CROW_ROUTE(app, "/video/updateUser").methods("POST"_method)([](const crow::request &req)
                                                                { return crow::response{updateUserHandle(req)}; });

    // 删除人员信息
    CROW_ROUTE(app, "/video/deleteUser").methods("POST"_method)([](const crow::request &req)
                                                                { return crow::response{deleteUserHandle(req)}; });

    app.port(appPort);

    // 启用多线程模式并运行应用程序
    app.multithreaded().run();
    // 释放结果集

    return 0;
}