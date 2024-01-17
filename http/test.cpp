#include <iostream>
#include <crow.h>

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
        return "Hello C++ Crow";
    });

    app.port(9876).multithreaded().run();
}
