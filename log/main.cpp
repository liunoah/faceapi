#include <spdlog/spdlog.h>

    // 创建控制台日志记录器
    auto console_logger = spdlog::stdout_logger_mt("console");

    // 创建文件日志记录器
    auto file_logger = spdlog::basic_logger_mt("file", "log.txt");
void initLogger(spdlog::level::level_enum logLevel) {


    // 设置控制台和文件日志记录器的日志等级
    console_logger->set_level(logLevel);
    file_logger->set_level(logLevel);
}

int main() {
    // 初始化日志记录器，设置日志级别为 debug
    initLogger(spdlog::level::debug);

    // 打印日志消息
    console_logger->info("This is a log message to console.");
    file_logger->info("This is a log message to file.");
    file_logger->debug("This is a log message to file.");
    console_logger->debug("This is a debug message.");
    return 0;
}