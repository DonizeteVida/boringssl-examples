/*
 * util.cpp
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#include <iostream>
using namespace std;

#include "openssl/err.h";

void error(string message) {
	cerr << message << endl;
}

void assert(bool res, string message) {
	if (!res) {
		error(message);
		cout << "Error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
		exit(EXIT_FAILURE);
	}
}

bool write_file(char *file, char *content, int size) {
	FILE *fp = fopen(file, "w");
	if (!fp)
		return false;
	while (size-- > 0) {
		fputc(content[0], fp);
		content++;
	}
	fclose(fp);
	return true;
}

char* read_file(char *file) {
	FILE *fp = fopen(file, "r");
	if (!fp)
		return 0;
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *buf = (char*) malloc(sizeof(char) * size);
	for(int i = 0; i < size; i++) {
		buf[i] = fgetc(fp);
	}
	fclose(fp);
	return buf;
}
