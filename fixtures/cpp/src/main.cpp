#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::vector<std::uint8_t> readAllStdin() {
  std::vector<std::uint8_t> data;
  std::ios::sync_with_stdio(false);
  std::cin.tie(nullptr);

  constexpr std::size_t kChunk = 4096;
  std::uint8_t buf[kChunk];
  while (std::cin.good()) {
    std::cin.read(reinterpret_cast<char *>(buf), static_cast<std::streamsize>(kChunk));
    const std::streamsize got = std::cin.gcount();
    if (got <= 0) break;
    data.insert(data.end(), buf, buf + got);
  }
  return data;
}

static std::vector<std::uint8_t> readAllFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  f.seekg(0, std::ios::end);
  const std::streamoff size = f.tellg();
  if (size <= 0) return {};
  f.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  f.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(data.size()));
  return data;
}

static std::uint32_t readLe32(const std::uint8_t *p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

static void crashNow() {
  volatile int *p = nullptr;
  *p = 1;
}

static void handleInput(const std::vector<std::uint8_t> &data) {
  if (data.size() < 8) return;
  if (std::memcmp(data.data(), "AFLPPMCP", 8) != 0) return;

  // Multi-step compare to make it slightly more interesting than a single byte check.
  if (data.size() >= 16 && std::memcmp(data.data() + 8, "CRASHME!", 8) == 0) {
    crashNow();
  }

  // A couple of additional branches (useful for smoke coverage signals).
  if (data.size() >= 20) {
    const std::uint32_t v = readLe32(data.data() + 16);
    if (v == 0x1337c0deU) {
      std::cout << "path:cmp1\n";
    } else if (v == 0xdeadbeefU) {
      std::cout << "path:cmp2\n";
    }
  }

  // Intentional unsafe copy: may be caught under ASAN builds.
  if (data.size() >= 12 && data[8] == 'B' && data[9] == 'U' && data[10] == 'F') {
    const std::uint8_t len = data[11];
    char buf[16];
    std::memcpy(buf, data.data() + 12, len);
    if (buf[0] == 'Z') std::cout << "path:buf\n";
  }
}

int main(int argc, char **argv) {
  std::vector<std::uint8_t> data;
  if (argc == 2) {
    data = readAllFile(argv[1]);
  } else {
    data = readAllStdin();
  }

  handleInput(data);
  return 0;
}

