// FP guard for Layer E: `cpp.memory.reinterpret_cast` must NOT fire on
// `reinterpret_cast<T>(x)` whose target T is a type explicitly defined
// as safe by the C++ aliasing rules — byte-pointer family, void*,
// integer round-trip, BSD socket address family.

#include <cstddef>
#include <cstdint>

struct sockaddr {
    int family;
};
struct sockaddr_in {
    int family;
    int port;
};

void byte_view(int* p) {
    auto* a = reinterpret_cast<uint8_t*>(p);
    auto* b = reinterpret_cast<const uint8_t*>(p);
    auto* c = reinterpret_cast<unsigned char*>(p);
    auto* d = reinterpret_cast<char*>(p);
    auto* e = reinterpret_cast<const std::byte*>(p);
    (void)a; (void)b; (void)c; (void)d; (void)e;
}

void* synth() {
    return reinterpret_cast<void*>(0x08000000);
}

uintptr_t roundtrip(int* p) {
    return reinterpret_cast<uintptr_t>(p);
}

void socket_pun(sockaddr_in* in) {
    auto* s = reinterpret_cast<sockaddr*>(in);
    (void)s;
}
