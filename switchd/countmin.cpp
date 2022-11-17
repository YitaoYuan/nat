#include "tests/countmin_test.hpp"

GlobalConfig global_cfg;

int main(int argc, char *argv[]) {
	global_cfg.parse(argc, argv);
    if (global_cfg.p4_name == "")
        global_cfg.p4_name = "countmin";

    CountMinTest test(global_cfg);
    
    test.initialize();
    // test.print_tables();
    test.start();

    cout << "Type `Ctrl+C` to exit" << endl;
    while(1);

    return 0;
}
