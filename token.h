// token.h

#ifndef TOKEN_H
#define TOKEN_H

#include <string>

std::string generateToken();
bool validateToken(const std::string& token);
void invalidateToken(const std::string& token);

#endif