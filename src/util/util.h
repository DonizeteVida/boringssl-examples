/*
 * util.h
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#ifndef UTIL_UTIL_H_
#define UTIL_UTIL_H_

#include <iostream>


void error(std::string);
void assert(bool, std::string);
bool write_file(char* file, char* content);
char* read_file(char* file);


#endif /* UTIL_UTIL_H_ */
