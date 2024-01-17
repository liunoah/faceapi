#include <iostream>
#include <string>

int main() {
    std::string url = "https://expo.com/chat/";

    // 寻找第三个斜杠的位置
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

    return 0;
}