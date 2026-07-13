#include "usk_sha256.h"

#include <array>
#include <stdexcept>
#include <string>

int main()
{
    usk::base::Sha256 abc;
    const std::string value = "abc";
    abc.update(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size());
    if (abc.finish() !=
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        return 1;
    }

    bool refused_second_finish = false;
    try {
        (void)abc.finish();
    } catch (const std::logic_error&) {
        refused_second_finish = true;
    }
    if (!refused_second_finish) {
        return 2;
    }

    usk::base::Sha256 million_a;
    std::array<unsigned char, 1000> block{};
    block.fill(static_cast<unsigned char>('a'));
    for (int index = 0; index < 1000; ++index) {
        million_a.update(block.data(), block.size());
    }
    if (million_a.finish() !=
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") {
        return 3;
    }

    usk::base::Sha256 invalid;
    bool refused_null = false;
    try {
        invalid.update(nullptr, 1);
    } catch (const std::logic_error&) {
        refused_null = true;
    }
    return refused_null ? 0 : 4;
}
