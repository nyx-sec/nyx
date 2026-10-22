#include <cstdlib>

struct Foo { int x; };

// Members acquired in a constructor are released by the destructor.
// Expected: no resource findings.
class Buffer {
public:
    Buffer(size_t n) { data_ = (char *)malloc(n); }
    ~Buffer() { free(data_); }
    char *data_;
};

class Holder {
    Foo *f_;
public:
    Holder() { f_ = new Foo(); }
    ~Holder() { delete f_; }
};
