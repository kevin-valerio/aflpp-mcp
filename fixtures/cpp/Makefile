BUILD_DIR ?= build

.PHONY: all clean

all:
	cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cmake --build "$(BUILD_DIR)" -j

clean:
	rm -rf "$(BUILD_DIR)"

