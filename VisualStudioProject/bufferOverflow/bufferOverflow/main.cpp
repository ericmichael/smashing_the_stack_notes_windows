#pragma check_stack(off)

#include <string.h>
#include <stdio.h> 
#include <iostream>
using namespace std;

void dumb(char * word)
{
	char temp[500];
	strcpy(temp, word);
	cout << temp;
}
int main(int argc, char* argv[])
{
	dumb(argv[1]);
	return 0;
}