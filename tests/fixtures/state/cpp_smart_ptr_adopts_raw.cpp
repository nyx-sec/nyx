#include <memory>

struct Foo { int x; };

// Smart pointers take ownership of the raw pointer they are built from.
// Expected: no resource findings.
void from_new() {
    std::unique_ptr<Foo> p(new Foo());
    p->x = 1;
}

void shared_from_new() {
    std::shared_ptr<Foo> s(new Foo());
    s->x = 2;
}

void from_raw() {
    Foo *raw = new Foo();
    std::unique_ptr<Foo> p(raw);
}

void reset_raw(std::unique_ptr<Foo> &p) {
    Foo *raw = new Foo();
    p.reset(raw);
}
