/*
 * util.cpp
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#include <iostream>
#include <fstream>
using namespace std;

#include <string.h>

#include "openssl/err.h";

void error(string message) {
	cerr << message << endl;
}

void assert(bool res, string message) {
	if (!res) {
		error(message);
		char buf[4096];
		ERR_error_string(ERR_get_error(), buf);
		cout << "Error: " << buf << endl;
		exit(EXIT_FAILURE);
	}
}

bool write_file(char *file, char *content) {
	ofstream stream(file);

	stream << content;

	stream.close();

	return true;
}

char* read_file(char *file) {
	ifstream stream(file);
	string str;
	while(getline(stream, str))
		;
	stream.close();
	int length = str.length();
	char* content = (char*) malloc(sizeof(char) * length);
	strcpy(content, str.c_str());

	return content;
}
