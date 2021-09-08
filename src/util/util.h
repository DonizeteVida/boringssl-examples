/*
 * util.h
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#ifndef UTIL_UTIL_H_
#define UTIL_UTIL_H_

#include <iostream>

typedef struct {
	uint8_t* data;
	size_t len;
} BINARY_DATA;

void error(std::string);
void assert(bool, std::string);
void write_binary(std::string name, BINARY_DATA data);
BINARY_DATA read_binary(std::string name);
void BINARY_DATA_free(BINARY_DATA& data);


#endif /* UTIL_UTIL_H_ */
