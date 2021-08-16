/*
 * util.cpp
 *
 *  Created on: Aug 14, 2021
 *      Author: doni
 */

#include <iostream>
using namespace std;

void error(string message) {
	cerr << message << endl;
}

void assert(bool res, string message) {
	if (!res) {
		error(message);
		exit(EXIT_FAILURE);
	}
}

