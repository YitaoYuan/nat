#include<bits/stdc++.h>
using std::unordered_map;
struct key{
    int x;
    /*key() {
        x = 0;
    }*/
    bool operator == (const key &_) const{
        return x == _.x;
    }
    bool operator < (const key &_) const{
        return x < _.x;
    }
};
struct val{
    int y;
};

size_t myhash(key x) {
    return x.x & 0xff;
}

bool myeq(key a, key b) {
    return a.x == b.x;
}

struct Hash{
    size_t operator ()(key x) const{
        return x.x & 0xff;
    }
};

struct Equal{
    bool operator ()(key a, key b) const{
        return a.x == b.x;
    }
};
//unordered_map<key, int, decltype(myhash), decltype(myeq)>mymap(1, &myhash, &myeq);
//unordered_map<key, int, decltype(myhash), decltype(myeq)>mymap(1, &myhash, &myeq);
//unordered_map<key, int, myhash, myeq>mymap;
unordered_map<key, int, Hash, Equal>mymap;

using std::string;
int main()
{
    string s("1bc");
    key x;
    x.x = 1;
    val y;
    y.y = 2;

    mymap[x] = 2;
    return 0;
}