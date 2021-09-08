/*
 * util.cpp
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include <string.h>

#include "openssl/err.h"

#include "util.h"

void error(string function) {
	char buf[4096];
	ERR_error_string(ERR_get_error(), buf);
	cerr << function << " " << "could not be performed" << endl;
	cout << "Error: " << buf << endl;
	exit(EXIT_FAILURE);
}

void write_binary(std::string name, BINARY_DATA data) {
	std::ofstream fs(name, std::ios::out | std::ios::binary);
	fs.write((char*) data.data, data.len);
}

BINARY_DATA read_binary(std::string name) {
	std::ifstream fs(name, std::ios::in | std::ios::binary);

	fs.seekg(0, std::ios::end);
	std::streampos size = fs.tellg();
	fs.seekg(0, std::ios::beg);
	char* buf = new char[size];
	fs.read(buf, size);

	return (BINARY_DATA) { (uint8_t*) buf, size };
}

void BINARY_DATA_free(BINARY_DATA& data) {
	delete(data.data);
	data.data = 0;
	data.len = 0;
}
