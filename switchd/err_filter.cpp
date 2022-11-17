#include <iostream>
#include <string>
using namespace std;

int main() {
	string str;
	while(getline(cin, str)) {
		if (str.find("tableEntryGetFirst", 0) != string::npos)
			continue;
		cout << str << endl;
	}
	return 0;
}
