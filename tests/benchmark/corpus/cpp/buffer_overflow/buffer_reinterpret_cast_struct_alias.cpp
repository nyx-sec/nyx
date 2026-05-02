// Vulnerable counterpart to `cpp/safe/safe_reinterpret_cast_byte_pointer.cpp`.
// `reinterpret_cast<UserStruct*>(buf)` (or any user-defined struct /
// class pointer target) is a genuine strict-aliasing UB risk: the
// program writes through a pointer to one type while the underlying
// storage was written as another, violating [basic.lval]/11.  The
// `cpp.memory.reinterpret_cast` pattern must continue to fire on these.

struct UserStruct {
    int a;
    int b;
};

UserStruct* alias_byte_buffer(char* buf) {
    return reinterpret_cast<UserStruct*>(buf);
}
