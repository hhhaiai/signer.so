#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace recovered {

using Block = std::array<std::uint8_t, 16>;
using Key256 = std::array<std::uint8_t, 32>;
using Sha256State = std::array<std::uint32_t, 8>;

// Fixed AES-256 material recovered from the protected native program.
constexpr Key256 kRecoveredAesKey = {
    0xff,0xb5,0xe5,0xf9,0xc8,0x62,0xb6,0x37,0xd1,0x33,0x51,0xc2,0x92,0x63,0x3e,0x39,
    0x96,0x5a,0x3c,0x2d,0x03,0x7e,0xd6,0x4d,0xff,0xf5,0x38,0x8e,0x11,0xd8,0x0d,0xb3
};

// Fixed HMAC-SHA256 key loaded word-by-word by libsigner.so+0xf9014..0xf9298.
constexpr std::array<std::uint8_t, 32> kRecoveredHmacKey = {
    0xca,0xab,0x83,0x44,0x4a,0x21,0x46,0x39,0x2a,0xbb,0x96,0xb6,0x42,0x30,0x61,0x55,
    0x29,0xa7,0x70,0xc6,0x3c,0x16,0x3c,0x1c,0x75,0x28,0x67,0x3e,0x06,0x71,0x72,0x8f
};

// libsigner.so materializes the eight source words at 0xf8xxx..0xf9a4c,
// then XORs each with 0xcccccccc at 0x115ca0..0x115ce8 before hashing the
// field-4 material. This is a fixed custom SHA-256 initial chaining state.
constexpr Sha256State kRecoveredField4InitialState = {
    0xcd46a0de,0xd5c62fe0,0x02cb3985,0xfd4a15a3,
    0x07cad499,0x63840dbf,0x51698010,0xca03ff52
};

class BionicRandom {
public:
    explicit BionicRandom(std::uint32_t seedValue) {
        seed(seedValue);
    }

    std::uint32_t next() {
        state_[front_] += state_[rear_];
        const std::uint32_t value = (state_[front_] >> 1) & 0x7fffffffU;
        front_ = (front_ + 1) % state_.size();
        rear_ = (rear_ + 1) % state_.size();
        return value;
    }

private:
    void seed(std::uint32_t value) {
        state_[0] = value;
        for (std::size_t i = 1; i < state_.size(); ++i) {
            const std::int64_t previous = static_cast<std::int32_t>(state_[i - 1]);
            const std::int64_t high = previous / 127773;
            const std::int64_t low = previous % 127773;
            std::int64_t nextValue = 16807 * low - 2836 * high;
            if (nextValue <= 0) nextValue += 0x7fffffff;
            state_[i] = static_cast<std::uint32_t>(nextValue);
        }
        front_ = 3;
        rear_ = 0;
        for (std::size_t i = 0; i < 10 * state_.size(); ++i) next();
    }

    std::array<std::uint32_t, 31> state_{};
    std::size_t front_ = 3;
    std::size_t rear_ = 0;
};

Block deriveIv(std::uint32_t timeSeconds) {
    BionicRandom random(timeSeconds);
    Block iv{};
    for (std::size_t wordIndex = 0; wordIndex < 4; ++wordIndex) {
        const std::uint32_t word = random.next() ^ random.next();
        iv[wordIndex * 4] = static_cast<std::uint8_t>(word >> 24);
        iv[wordIndex * 4 + 1] = static_cast<std::uint8_t>(word >> 16);
        iv[wordIndex * 4 + 2] = static_cast<std::uint8_t>(word >> 8);
        iv[wordIndex * 4 + 3] = static_cast<std::uint8_t>(word);
    }
    return iv;
}

constexpr std::array<std::uint8_t, 256> kSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

constexpr std::array<std::uint8_t, 15> kRcon = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

std::uint8_t xtime(std::uint8_t value) {
    return static_cast<std::uint8_t>((value << 1) ^ ((value & 0x80) ? 0x1b : 0));
}

void addRoundKey(Block& state, const std::uint8_t* roundKey) {
    for (std::size_t i = 0; i < state.size(); ++i) state[i] ^= roundKey[i];
}

void subBytes(Block& state) {
    for (std::uint8_t& value : state) value = kSbox[value];
}

void shiftRows(Block& state) {
    Block copy = state;
    for (int row = 0; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            state[4 * column + row] = copy[4 * ((column + row) & 3) + row];
        }
    }
}

void mixColumns(Block& state) {
    for (int column = 0; column < 4; ++column) {
        std::uint8_t* value = state.data() + 4 * column;
        const std::uint8_t all = value[0] ^ value[1] ^ value[2] ^ value[3];
        const std::uint8_t first = value[0];
        value[0] ^= all ^ xtime(static_cast<std::uint8_t>(value[0] ^ value[1]));
        value[1] ^= all ^ xtime(static_cast<std::uint8_t>(value[1] ^ value[2]));
        value[2] ^= all ^ xtime(static_cast<std::uint8_t>(value[2] ^ value[3]));
        value[3] ^= all ^ xtime(static_cast<std::uint8_t>(value[3] ^ first));
    }
}

std::array<std::uint8_t, 240> expandKey(const Key256& key) {
    std::array<std::uint8_t, 240> expanded{};
    std::memcpy(expanded.data(), key.data(), key.size());
    std::size_t generated = key.size();
    int rcon = 1;
    std::array<std::uint8_t, 4> word{};
    while (generated < expanded.size()) {
        std::memcpy(word.data(), expanded.data() + generated - 4, word.size());
        if ((generated % 32) == 0) {
            const std::uint8_t first = word[0];
            word[0] = kSbox[word[1]] ^ kRcon[rcon++];
            word[1] = kSbox[word[2]];
            word[2] = kSbox[word[3]];
            word[3] = kSbox[first];
        } else if ((generated % 32) == 16) {
            for (std::uint8_t& value : word) value = kSbox[value];
        }
        for (std::size_t i = 0; i < word.size() && generated < expanded.size(); ++i) {
            expanded[generated] = expanded[generated - 32] ^ word[i];
            ++generated;
        }
    }
    return expanded;
}

Block aes256EncryptBlock(const Key256& key, const Block& input) {
    const auto expanded = expandKey(key);
    Block state = input;
    addRoundKey(state, expanded.data());
    for (int round = 1; round < 14; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expanded.data() + round * 16);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expanded.data() + 14 * 16);
    return state;
}

std::vector<std::uint8_t> aes256CbcEncryptPkcs7(
        const Key256& key,
        const Block& iv,
        const std::uint8_t* plaintext,
        std::size_t plaintextSize) {
    std::vector<std::uint8_t> padded(plaintext, plaintext + plaintextSize);
    const std::uint8_t padding = static_cast<std::uint8_t>(16 - (plaintextSize % 16));
    padded.insert(padded.end(), padding, padding);

    std::vector<std::uint8_t> ciphertext(padded.size());
    Block previous = iv;
    for (std::size_t offset = 0; offset < padded.size(); offset += previous.size()) {
        Block block{};
        for (std::size_t i = 0; i < block.size(); ++i) {
            block[i] = static_cast<std::uint8_t>(padded[offset + i] ^ previous[i]);
        }
        previous = aes256EncryptBlock(key, block);
        std::memcpy(ciphertext.data() + offset, previous.data(), previous.size());
    }
    return ciphertext;
}

constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

std::uint32_t rotateRight(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

std::array<std::uint8_t, 32> sha256WithInitialState(
        const std::uint8_t* data,
        std::size_t size,
        Sha256State hash) {
    std::vector<std::uint8_t> padded;
    if (size != 0) padded.insert(padded.end(), data, data + size);
    padded.push_back(0x80);
    while ((padded.size() % 64) != 56) padded.push_back(0);
    const std::uint64_t bitLength = static_cast<std::uint64_t>(size) * 8;
    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<std::uint8_t>(bitLength >> shift));
    }

    for (std::size_t offset = 0; offset < padded.size(); offset += 64) {
        std::array<std::uint32_t, 64> schedule{};
        for (std::size_t i = 0; i < 16; ++i) {
            const std::uint8_t* word = padded.data() + offset + i * 4;
            schedule[i] = (static_cast<std::uint32_t>(word[0]) << 24)
                    | (static_cast<std::uint32_t>(word[1]) << 16)
                    | (static_cast<std::uint32_t>(word[2]) << 8)
                    | word[3];
        }
        for (std::size_t i = 16; i < schedule.size(); ++i) {
            const std::uint32_t s0 = rotateRight(schedule[i - 15], 7)
                    ^ rotateRight(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
            const std::uint32_t s1 = rotateRight(schedule[i - 2], 17)
                    ^ rotateRight(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
            schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
        }

        std::uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
        std::uint32_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        for (std::size_t i = 0; i < schedule.size(); ++i) {
            const std::uint32_t big1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const std::uint32_t choose = (e & f) ^ (~e & g);
            const std::uint32_t temp1 = h + big1 + choose + kSha256RoundConstants[i] + schedule[i];
            const std::uint32_t big0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = big0 + majority;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
        hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
    }

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < hash.size(); ++i) {
        digest[i * 4] = static_cast<std::uint8_t>(hash[i] >> 24);
        digest[i * 4 + 1] = static_cast<std::uint8_t>(hash[i] >> 16);
        digest[i * 4 + 2] = static_cast<std::uint8_t>(hash[i] >> 8);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(hash[i]);
    }
    return digest;
}

std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t size) {
    constexpr Sha256State initialState = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    return sha256WithInitialState(data, size, initialState);
}

std::array<std::uint8_t, 32> hmacSha256(
        const std::uint8_t* key,
        std::size_t keySize,
        const std::uint8_t* message,
        std::size_t messageSize) {
    std::array<std::uint8_t, 64> keyBlock{};
    if (keySize > keyBlock.size()) {
        const auto digest = sha256(key, keySize);
        std::memcpy(keyBlock.data(), digest.data(), digest.size());
    } else {
        std::memcpy(keyBlock.data(), key, keySize);
    }
    std::vector<std::uint8_t> inner(keyBlock.size() + messageSize);
    std::vector<std::uint8_t> outer(keyBlock.size() + 32);
    for (std::size_t i = 0; i < keyBlock.size(); ++i) {
        inner[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x36);
        outer[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x5c);
    }
    std::memcpy(inner.data() + keyBlock.size(), message, messageSize);
    const auto innerDigest = sha256(inner.data(), inner.size());
    std::memcpy(outer.data() + keyBlock.size(), innerDigest.data(), innerDigest.size());
    return sha256(outer.data(), outer.size());
}

// Halfwords dumped from state+0x10 before libsigner.so+0x13531c. The native
// routine indexes this table in reverse bit order.
constexpr std::array<std::uint16_t, 16> kCodewordBasisInMemoryOrder = {
    0x0002,0x0022,0x0220,0x2220,0x8200,0x0a00,0x0120,0xa221,
    0x0401,0xa42a,0xb20a,0x1839,0xb824,0x0668,0xcd15,0xd0aa
};

std::uint16_t encodeCorrection(std::uint16_t code) {
    const std::uint16_t input = static_cast<std::uint16_t>(code * 2u + 3u);
    std::uint16_t output = 0;
    for (int bit = 0; bit < 16; ++bit) {
        if ((input & (1u << bit)) != 0) output ^= kCodewordBasisInMemoryOrder[15 - bit];
    }
    return output;
}

struct NativeInputs {
    std::uint32_t timeSeconds;
    std::vector<std::uint16_t> correctionCodes;
    std::array<std::uint8_t, 4> field2;
    std::array<std::uint8_t, 20> certificateSha1;
    std::vector<std::uint8_t> nativePlaintext;
    bool state;
};

std::vector<std::uint16_t> buildEnvironmentHalfwords(const NativeInputs& inputs) {
    std::size_t size = 8;
    while (inputs.correctionCodes.size() > size) size += 8;
    if (size > 248) std::abort();
    std::vector<std::uint16_t> halfwords(size);
    for (std::size_t index = 0; index < halfwords.size(); ++index) {
        halfwords[index] = encodeCorrection(static_cast<std::uint16_t>(0x40 + (index % 8)));
    }
    for (std::size_t index = 0; index < inputs.correctionCodes.size(); ++index) {
        halfwords[index] = encodeCorrection(inputs.correctionCodes[index]);
    }
    return halfwords;
}

void appendHalfwordBigEndian(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

std::array<std::uint8_t, 32> deriveField4(const NativeInputs& inputs) {
    const auto emptyDigest = sha256(nullptr, 0);
    const auto environmentHalfwords = buildEnvironmentHalfwords(inputs);
    std::vector<std::uint8_t> material;
    material.insert(material.end(), inputs.certificateSha1.begin(), inputs.certificateSha1.end());
    material.push_back(0x00);
    material.push_back(static_cast<std::uint8_t>(environmentHalfwords.size()));
    for (std::uint16_t halfword : environmentHalfwords) {
        appendHalfwordBigEndian(material, halfword);
    }
    material.insert(material.end(), inputs.field2.begin(), inputs.field2.end());
    material.insert(material.end(), emptyDigest.begin(), emptyDigest.end());
    material.push_back(inputs.state ? 1 : 0);
    material.insert(material.end(), inputs.nativePlaintext.begin(), inputs.nativePlaintext.end());
    return sha256WithInitialState(
            material.data(), material.size(), kRecoveredField4InitialState);
}

std::vector<std::uint8_t> buildPayload(const NativeInputs& inputs) {
    const auto field4 = deriveField4(inputs);
    const auto emptyDigest = sha256(nullptr, 0);
    const auto environmentHalfwords = buildEnvironmentHalfwords(inputs);
    std::vector<std::uint8_t> payload;
    payload.reserve(97 + environmentHalfwords.size() * 2);
    payload.push_back(0x01);
    payload.push_back(0x00);
    payload.push_back(static_cast<std::uint8_t>(environmentHalfwords.size()));
    for (std::uint16_t halfword : environmentHalfwords) {
        appendHalfwordBigEndian(payload, halfword);
    }
    payload.push_back(0x02);
    for (auto it = inputs.field2.rbegin(); it != inputs.field2.rend(); ++it) {
        payload.push_back(*it);
    }
    payload.push_back(0x03);
    payload.insert(payload.end(), inputs.certificateSha1.begin(), inputs.certificateSha1.end());
    payload.push_back(0x04);
    payload.insert(payload.end(), field4.begin(), field4.end());
    payload.push_back(0x05);
    payload.insert(payload.end(), emptyDigest.begin(), emptyDigest.end());
    payload.push_back(0x06);
    payload.push_back(inputs.state ? 1 : 0);
    return payload;
}

std::vector<std::uint8_t> sign(const NativeInputs& inputs) {
    const Block iv = deriveIv(inputs.timeSeconds);
    const auto payload = buildPayload(inputs);
    const auto ciphertext = aes256CbcEncryptPkcs7(
            kRecoveredAesKey, iv, payload.data(), payload.size());
    const auto tag = hmacSha256(kRecoveredHmacKey.data(), kRecoveredHmacKey.size(),
            ciphertext.data(), ciphertext.size());
    std::vector<std::uint8_t> signature;
    signature.reserve(iv.size() + ciphertext.size() + tag.size());
    signature.insert(signature.end(), iv.begin(), iv.end());
    signature.insert(signature.end(), ciphertext.begin(), ciphertext.end());
    signature.insert(signature.end(), tag.begin(), tag.end());
    return signature;
}

template <std::size_t N>
bool equal(const std::array<std::uint8_t, N>& left, const std::array<std::uint8_t, N>& right) {
    return std::memcmp(left.data(), right.data(), N) == 0;
}

template <std::size_t N>
bool equal(const std::vector<std::uint8_t>& left, const std::array<std::uint8_t, N>& right) {
    return left.size() == right.size() && std::memcmp(left.data(), right.data(), N) == 0;
}

template <std::size_t N>
void printHex(const std::array<std::uint8_t, N>& bytes) {
    for (std::uint8_t value : bytes) std::printf("%02x", value);
}

void printHex(const std::vector<std::uint8_t>& bytes) {
    for (std::uint8_t value : bytes) std::printf("%02x", value);
}

int hexNibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> parseHex(const char* value) {
    const std::size_t size = std::strlen(value);
    if ((size & 1U) != 0) return {};
    std::vector<std::uint8_t> bytes(size / 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const int high = hexNibble(value[index * 2]);
        const int low = hexNibble(value[index * 2 + 1]);
        if (high < 0 || low < 0) return {};
        bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return bytes;
}

std::vector<std::uint16_t> parseCorrectionCodes(const char* value) {
    std::vector<std::uint16_t> codes;
    const char* cursor = value;
    while (*cursor != '\0') {
        char* end = nullptr;
        const unsigned long code = std::strtoul(cursor, &end, 16);
        if (end == cursor || code > 0x7fff || (*end != ',' && *end != '\0')) return {};
        codes.push_back(static_cast<std::uint16_t>(code));
        cursor = *end == ',' ? end + 1 : end;
    }
    return codes;
}

}  // namespace recovered

int main(int argc, char** argv) {
    using namespace recovered;
    const Key256& key = kRecoveredAesKey;
    const Block input = {
        0x3a,0x27,0x3b,0xb6,0xbc,0x3e,0xcb,0xa0,0xbf,0x89,0xd2,0x36,0xef,0xd3,0xd8,0xb6
    };
    const Block expected = {
        0x51,0xda,0x68,0x94,0x51,0x26,0x60,0xbd,0x1e,0x98,0x09,0xe7,0xc1,0x7c,0x38,0x98
    };
    if (!equal(aes256EncryptBlock(key, input), expected)) {
        std::fprintf(stderr, "AES-256 Pixel first-block vector failed\n");
        return EXIT_FAILURE;
    }

    const Block expectedIv = {
        0x3b,0x27,0x33,0x62,0x21,0x8b,0x18,0x6a,0x73,0xe7,0x34,0x97,0x75,0xb9,0x3f,0x11
    };
    const Block iv = deriveIv(1760000000U);
    if (!equal(iv, expectedIv)) {
        std::fprintf(stderr, "Bionic rand-derived Pixel IV failed\n");
        return EXIT_FAILURE;
    }
    const char nativePlaintext[] = "0123456789abcdef"
            "abc123"
            "CN"
            "2026-07-10T00:00:00.000+0800"
            "Pixel 9 Pro"
            "phone"
            "sandbox"
            "11111111-1111-1111-1111-111111111111"
            "android"
            "15"
            "1400000"
            "session"
            "android4.38.5"
            "93.67.0";
    const NativeInputs inputs = {
        1760000000U,
        {0x2b,0x36,0x25,0x05},
        {0x00,0x01,0x02,0x03},
        {0x16,0x4a,0x86,0xfa,0xf3,0x0e,0x41,0x2b,0x59,0x22,
         0x3a,0x36,0xcc,0xbe,0x0f,0x6e,0x46,0xe4,0x09,0x58},
        std::vector<std::uint8_t>(nativePlaintext, nativePlaintext + sizeof(nativePlaintext) - 1),
        true
    };
    if (inputs.nativePlaintext.size() != 154) {
        std::fprintf(stderr, "Pixel native plaintext length failed\n");
        return EXIT_FAILURE;
    }
    const auto payload = buildPayload(inputs);
    const std::array<std::uint8_t, 32> expectedField4 = {
        0xfe,0xf6,0xae,0x81,0xab,0x7a,0x34,0xb0,0xc9,0x38,0x95,0x2b,0xa4,0x06,0xbb,0xee,
        0x57,0xd4,0x7d,0x7b,0x82,0xa9,0x9f,0xde,0x1a,0x6b,0x84,0xe4,0x2e,0x10,0x53,0x80
    };
    if (!equal(deriveField4(inputs), expectedField4)) {
        std::fprintf(stderr, "custom-state SHA-256 Pixel field-4 vector failed\n");
        return EXIT_FAILURE;
    }
    const std::array<std::uint8_t, 128> expectedCiphertext = {
        0x51,0xda,0x68,0x94,0x51,0x26,0x60,0xbd,0x1e,0x98,0x09,0xe7,0xc1,0x7c,0x38,0x98,
        0xa2,0xd0,0xc5,0x50,0x8f,0x89,0xe6,0xc3,0x02,0x2e,0x6c,0x8f,0x7b,0x44,0x27,0x97,
        0xab,0xef,0x7d,0x1d,0x32,0xd8,0xa0,0x4d,0x88,0x7d,0x2d,0x1b,0xf2,0x4b,0x19,0xb1,
        0xf9,0xab,0x2e,0x87,0x8f,0x79,0xe9,0xe4,0x40,0x3f,0x2f,0xbb,0x71,0xee,0x56,0x09,
        0x44,0x30,0x39,0xc0,0xce,0x6f,0xc3,0x55,0x89,0x20,0x96,0xd6,0x3e,0x69,0x7e,0x9c,
        0xa2,0x79,0x4c,0xf0,0x62,0x8c,0x44,0x03,0xe0,0xd6,0xe9,0xe4,0x52,0xc3,0x56,0xcb,
        0xf8,0x81,0xe5,0xae,0xbd,0x43,0x1e,0x2b,0x58,0x3b,0x6d,0x92,0x38,0x75,0xd3,0xeb,
        0x9b,0x3b,0x2d,0xe5,0x20,0xab,0x29,0x1c,0xa7,0x2a,0x1f,0x1c,0xd6,0x61,0xd6,0xaf
    };
    const auto ciphertext = aes256CbcEncryptPkcs7(key, iv, payload.data(), payload.size());
    if (ciphertext.size() != expectedCiphertext.size()
            || std::memcmp(ciphertext.data(), expectedCiphertext.data(), expectedCiphertext.size()) != 0) {
        std::fprintf(stderr, "AES-256-CBC Pixel 128-byte vector failed\n");
        return EXIT_FAILURE;
    }
    const std::array<std::uint8_t, 32> expectedTag = {
        0x51,0x0d,0x95,0x2d,0x14,0x92,0x1d,0xb3,0xae,0x61,0x53,0x7b,0x5f,0xcc,0xc2,0x1e,
        0x45,0x55,0x4b,0xf7,0x2a,0x6d,0x10,0x78,0x16,0xfb,0xbf,0x28,0xeb,0xd8,0xf6,0xf7
    };
    const auto tag = hmacSha256(kRecoveredHmacKey.data(), kRecoveredHmacKey.size(),
            ciphertext.data(), ciphertext.size());
    if (!equal(tag, expectedTag)) {
        std::fprintf(stderr, "HMAC-SHA256 Pixel tag vector failed\n");
        return EXIT_FAILURE;
    }
    const std::array<std::uint8_t, 176> expectedSignature = {
        0x3b,0x27,0x33,0x62,0x21,0x8b,0x18,0x6a,0x73,0xe7,0x34,0x97,0x75,0xb9,0x3f,0x11,
        0x51,0xda,0x68,0x94,0x51,0x26,0x60,0xbd,0x1e,0x98,0x09,0xe7,0xc1,0x7c,0x38,0x98,
        0xa2,0xd0,0xc5,0x50,0x8f,0x89,0xe6,0xc3,0x02,0x2e,0x6c,0x8f,0x7b,0x44,0x27,0x97,
        0xab,0xef,0x7d,0x1d,0x32,0xd8,0xa0,0x4d,0x88,0x7d,0x2d,0x1b,0xf2,0x4b,0x19,0xb1,
        0xf9,0xab,0x2e,0x87,0x8f,0x79,0xe9,0xe4,0x40,0x3f,0x2f,0xbb,0x71,0xee,0x56,0x09,
        0x44,0x30,0x39,0xc0,0xce,0x6f,0xc3,0x55,0x89,0x20,0x96,0xd6,0x3e,0x69,0x7e,0x9c,
        0xa2,0x79,0x4c,0xf0,0x62,0x8c,0x44,0x03,0xe0,0xd6,0xe9,0xe4,0x52,0xc3,0x56,0xcb,
        0xf8,0x81,0xe5,0xae,0xbd,0x43,0x1e,0x2b,0x58,0x3b,0x6d,0x92,0x38,0x75,0xd3,0xeb,
        0x9b,0x3b,0x2d,0xe5,0x20,0xab,0x29,0x1c,0xa7,0x2a,0x1f,0x1c,0xd6,0x61,0xd6,0xaf,
        0x51,0x0d,0x95,0x2d,0x14,0x92,0x1d,0xb3,0xae,0x61,0x53,0x7b,0x5f,0xcc,0xc2,0x1e,
        0x45,0x55,0x4b,0xf7,0x2a,0x6d,0x10,0x78,0x16,0xfb,0xbf,0x28,0xeb,0xd8,0xf6,0xf7
    };
    if (!equal(sign(inputs), expectedSignature)) {
        std::fprintf(stderr, "complete source-built Pixel signature failed\n");
        return EXIT_FAILURE;
    }

    struct CodewordVector { std::uint16_t code; std::uint16_t expected; };
    constexpr CodewordVector vectors[] = {
        {0x2b, 0xd49d}, {0x36, 0xb5d3}, {0x25, 0xcacc}, {0x05, 0x6ee6},
        {0x40, 0x19be}, {0x41, 0xd2c3}, {0x42, 0x1fd6}, {0x43, 0x6c8f},
        {0x44, 0xa19a}, {0x45, 0x6ae7}, {0x46, 0xa7f2}, {0x47, 0xcc92}
    };
    for (const auto& vector : vectors) {
        const std::uint16_t actual = encodeCorrection(vector.code);
        if (actual != vector.expected) {
            std::fprintf(stderr, "codeword 0x%02x expected=0x%04x actual=0x%04x\n",
                    vector.code, vector.expected, actual);
            return EXIT_FAILURE;
        }
    }

    std::puts("recovered native primitives: PASS");
    std::puts("AES-256 Pixel first block: 51da6894512660bd1e9809e7c17c3898");
    std::puts("Bionic rand-derived Pixel IV: 3b273362218b186a73e7349775b93f11");
    std::puts("custom-state SHA-256 Pixel field 4: PASS");
    std::puts("source-built Pixel payload: 113 plaintext bytes -> 128 ciphertext bytes");
    std::puts("HMAC-SHA256 Pixel ciphertext tag: 32 bytes");
    std::puts("Pixel native result layout: 16 IV + 128 ciphertext + 32 tag = 176 bytes");
    std::puts("complete source-built Pixel 176-byte signature: PASS");
    std::puts("corrections: 2b=d49d 36=b5d3 25=cacc 05=6ee6");
    NativeInputs requested = inputs;
    bool customRequest = false;
    for (int index = 1; index < argc; ++index) {
        constexpr const char timePrefix[] = "--time-seconds=";
        constexpr const char trampolinePrefix[] = "--signer-code-trampoline-detected=";
        constexpr const char certificatePrefix[] = "--certificate-sha1=";
        constexpr const char plaintextPrefix[] = "--native-plaintext-hex=";
        constexpr const char statePrefix[] = "--state=";
        constexpr const char correctionsPrefix[] = "--correction-codes=";
        if (std::strncmp(argv[index], timePrefix, sizeof(timePrefix) - 1) == 0) {
            requested.timeSeconds = static_cast<std::uint32_t>(
                    std::strtoul(argv[index] + sizeof(timePrefix) - 1, nullptr, 10));
            customRequest = true;
        } else if (std::strncmp(argv[index], trampolinePrefix, sizeof(trampolinePrefix) - 1) == 0) {
            const char* value = argv[index] + sizeof(trampolinePrefix) - 1;
            if (std::strcmp(value, "true") == 0 || std::strcmp(value, "1") == 0) {
                requested.correctionCodes = {0x2b,0x36,0x25,0x05};
            } else if (std::strcmp(value, "false") == 0 || std::strcmp(value, "0") == 0) {
                requested.correctionCodes = {0x2b,0x36,0x05};
            } else {
                std::fprintf(stderr, "invalid trampoline value: %s\n", value);
                return EXIT_FAILURE;
            }
            customRequest = true;
        } else if (std::strncmp(argv[index], certificatePrefix, sizeof(certificatePrefix) - 1) == 0) {
            const auto bytes = parseHex(argv[index] + sizeof(certificatePrefix) - 1);
            if (bytes.size() != requested.certificateSha1.size()) {
                std::fprintf(stderr, "certificate SHA1 must be exactly 20 bytes\n");
                return EXIT_FAILURE;
            }
            std::memcpy(requested.certificateSha1.data(), bytes.data(), bytes.size());
            customRequest = true;
        } else if (std::strncmp(argv[index], plaintextPrefix, sizeof(plaintextPrefix) - 1) == 0) {
            const char* value = argv[index] + sizeof(plaintextPrefix) - 1;
            requested.nativePlaintext = parseHex(value);
            if (*value != '\0' && requested.nativePlaintext.empty()) {
                std::fprintf(stderr, "native plaintext must be even-length hexadecimal\n");
                return EXIT_FAILURE;
            }
            customRequest = true;
        } else if (std::strncmp(argv[index], statePrefix, sizeof(statePrefix) - 1) == 0) {
            const char* value = argv[index] + sizeof(statePrefix) - 1;
            if (std::strcmp(value, "true") == 0 || std::strcmp(value, "1") == 0) requested.state = true;
            else if (std::strcmp(value, "false") == 0 || std::strcmp(value, "0") == 0) requested.state = false;
            else {
                std::fprintf(stderr, "invalid state value: %s\n", value);
                return EXIT_FAILURE;
            }
            customRequest = true;
        } else if (std::strncmp(argv[index], correctionsPrefix, sizeof(correctionsPrefix) - 1) == 0) {
            const char* value = argv[index] + sizeof(correctionsPrefix) - 1;
            requested.correctionCodes = parseCorrectionCodes(value);
            if (*value != '\0' && requested.correctionCodes.empty()) {
                std::fprintf(stderr, "invalid comma-separated correction codes: %s\n", value);
                return EXIT_FAILURE;
            }
            customRequest = true;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", argv[index]);
            return EXIT_FAILURE;
        }
    }
    if (customRequest) {
        std::printf("SIGNATURE_HEX=");
        printHex(sign(requested));
        std::putchar('\n');
    }
    return EXIT_SUCCESS;
}
