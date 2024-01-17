#!/bin/bash

while true; do
    if ! ps -aux | grep -q "[t]estProject"; then
        echo "testProject is not running. Starting..."
        nohup /testProject &
    fi
    sleep 1
done#include <iostream>
#include <curl/curl.h>

int main() {
    CURL *curl;
    CURLcode res;

    // 初始化cURL
    curl_global_init(CURL_GLOBAL_ALL);

    // 创建cURL句柄
    curl = curl_easy_init();
    if (curl) {
        // 设置请求URL
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/api");

        // 设置POST请求
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // 设置POST数据
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "param1=value1&param2=value2");

        // 执行请求
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "cURL request failed: " << curl_easy_strerror(res) << std::endl;
        }

        // 清除cURL句柄
        curl_easy_cleanup(curl);
    }

    // 清除cURL全局环境
    curl_global_cleanup();

    return 0;
}