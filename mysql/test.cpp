#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>

sql::ResultSet* executeQuery(const std::string& sqlQuery) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;

    try {
        // 创建MySQL连接
        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect("tcp://localhost:3306/test", "root", "Admin@123");

        // 连接成功后的操作
        if (con) {
            std::cout << "Connected to MySQL!" << std::endl;
            // 创建一个 SQL 语句
            stmt = con->createStatement();
            // 使用 Statement 执行查询
            res = stmt->executeQuery(sqlQuery);
            return res;
        }
    } catch (sql::SQLException &e) {
        std::cout << "SQL Exception: " << e.what() << std::endl;
    }

    return nullptr;
}

int main() {
    std::string sqlQuery = "SELECT * FROM accessSource";
    sql::ResultSet *res = executeQuery(sqlQuery);

    if (res) {
        // 遍历结果集并提取数据
        while (res->next()) {
            int id = res->getInt("id");
            std::string dataPath = res->getString("dataPath");
            std::string channelNumber = res->getString("channelNumber");
            std::string type = res->getString("type");
            std::string address = res->getString("address");
            std::string connectionMethod = res->getString("connectionMethod");
            std::string username = res->getString("username");
            std::string password = res->getString("password");

            // 在这里处理提取到的数据
            // 可以将数据存储到自定义的数据结构中，或进行其他操作

            std::cout << "id: " << id << ", dataPath: " << dataPath << ", channelNumber: " << channelNumber << ", type: " << type << ", address: " << address << ", connectionMethod: " << connectionMethod << ", username: " << username << ", password: " << password << std::endl;
        }

        delete res;
    }

    return 0;
}