#include <vector>

struct Foo { int x; };

// Expected: no resource findings.
void store(std::vector<Foo *> &v) {
    Foo *f = new Foo();
    v.push_back(f);
}
