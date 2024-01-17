#include "crow.h"

int main()
{
    crow::SimpleApp app;

    // 创建一个简单的Crow应用

    CROW_ROUTE(app, "/uploadfile")
      .methods(crow::HTTPMethod::Post)([](const crow::request& req) {
          // 处理POST请求的"/uploadfile"路由

          crow::multipart::message file_message(req);
          // 解析请求中的multipart消息

          for (const auto& part : file_message.part_map)
          {
              const auto& part_name = part.first;
              const auto& part_value = part.second;
              CROW_LOG_DEBUG << "Part: " << part_name;
              // 输出部分的名称

              if ("InputFile" == part_name)
              {
                  // 如果部分名称为"InputFile"

                  // 提取文件名
                  auto headers_it = part_value.headers.find("Content-Disposition");
                  if (headers_it == part_value.headers.end())
                  {
                      // 检查是否存在"Content-Disposition"头部
                      CROW_LOG_ERROR << "No Content-Disposition found";
                      return crow::response(400);
                  }
                  auto params_it = headers_it->second.params.find("filename");
                  if (params_it == headers_it->second.params.end())
                  {
                      // 检查"InputFile"部分是否包含文件
                      CROW_LOG_ERROR << "Part with name \"InputFile\" should have a file";
                      return crow::response(400);
                  }
                  const std::string outfile_name = params_it->second;

                  for (const auto& part_header : part_value.headers)
                  {
                      const auto& part_header_name = part_header.first;
                      const auto& part_header_val = part_header.second;
                      CROW_LOG_DEBUG << "Header: " << part_header_name << '=' << part_header_val.value;
                      // 输出部分的头部信息
                      for (const auto& param : part_header_val.params)
                      {
                          const auto& param_key = param.first;
                          const auto& param_val = param.second;
                          CROW_LOG_DEBUG << " Param: " << param_key << ',' << param_val;
                          // 输出部分头部的参数
                      }
                  }

                  // 创建一个新文件，使用提取的文件名，并将文件内容写入其中
                  std::ofstream out_file(outfile_name);
                  if (!out_file)
                  {
                      // 检查文件是否成功打开
                      CROW_LOG_ERROR << "Write to file failed\n";
                      continue;
                  }
                  out_file << part_value.body;
                  out_file.close();
                  CROW_LOG_INFO << "Contents written to " << outfile_name << '\n';

                  // 打印文件大小和文件名
                  std::ifstream in_file(outfile_name, std::ios::binary | std::ios::ate);
                  if (in_file)
                  {
                      std::streampos file_size = in_file.tellg();
                      CROW_LOG_INFO << "File size: " << file_size << " bytes";
                      CROW_LOG_INFO << "File name: " << outfile_name;
                      in_file.close();
                  }
              }
              else
              {
                  CROW_LOG_DEBUG << "Value: " << part_value.body << '\n';
                  // 输出部分的内容
              }
          }
          return crow::response(200);
          // 返回HTTP响应码200
      });

    // 启用所有日志
    app.loglevel(crow::LogLevel::Debug);

    // 设置应用监听的端口号为18080，并启用多线程模式运行应用
    app.port(18080)
      .multithreaded()
      .run();

    return 0;
}