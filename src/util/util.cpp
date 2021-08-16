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
		printf("\nerror: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
}

