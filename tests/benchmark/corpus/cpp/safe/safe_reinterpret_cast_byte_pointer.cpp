// Canonical safe `reinterpret_cast<T>(x)` shapes — Layer E in
// `src/ast.rs::is_cpp_cast_target_type_safe` recognises these as
// well-defined-by-aliasing-rules per [basic.lval]/11 and POSIX socket
// API contracts and suppresses the `cpp.memory.reinterpret_cast`
// pattern finding.
//
// Distilled from real-repo shapes:
//   - `reinterpret_cast<uint8_t*>(...)` — bitcoin/leveldb serialization
//   - `reinterpret_cast<const std::byte*>(...)` — bitcoin crc32c hashing
//   - `reinterpret_cast<void*>(0x08000000)` — bitcoin lockedpool synth
//   - `reinterpret_cast<uintptr_t>(...)` — bitcoin crc32c round-up
//   - `reinterpret_cast<sockaddr*>(...)` — bitcoin netif BSD socket pun

#include <cstddef>
#include <cstdint>

struct sockaddr {
    int family;
};
struct sockaddr_in {
    int family;
    int port;
};

void serialize_to_byte_buffer(int* dst) {
    auto* p = reinterpret_cast<uint8_t*>(dst);
    auto* q = reinterpret_cast<unsigned char*>(dst);
    auto* r = reinterpret_cast<char*>(dst);
    (void)p;
    (void)q;
    (void)r;
}

void hash_input_via_byte_view(const int* src) {
    const auto* a = reinterpret_cast<const uint8_t*>(src);
    const auto* b = reinterpret_cast<const std::byte*>(src);
    (void)a;
    (void)b;
}

void* make_synthetic_address() {
    return reinterpret_cast<void*>(0x08000000);
}

uintptr_t pointer_to_int(int* p) {
    return reinterpret_cast<uintptr_t>(p);
}

void bsd_socket_addr_pun(sockaddr_in* in) {
    auto* generic = reinterpret_cast<sockaddr*>(in);
    (void)generic;
}
