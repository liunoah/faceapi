# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /project/log

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /project/log/build

# Include any dependencies generated for this target.
include CMakeFiles/MyExecutable.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/MyExecutable.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/MyExecutable.dir/flags.make

CMakeFiles/MyExecutable.dir/main.cpp.o: CMakeFiles/MyExecutable.dir/flags.make
CMakeFiles/MyExecutable.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/project/log/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/MyExecutable.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/MyExecutable.dir/main.cpp.o -c /project/log/main.cpp

CMakeFiles/MyExecutable.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MyExecutable.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /project/log/main.cpp > CMakeFiles/MyExecutable.dir/main.cpp.i

CMakeFiles/MyExecutable.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MyExecutable.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /project/log/main.cpp -o CMakeFiles/MyExecutable.dir/main.cpp.s

CMakeFiles/MyExecutable.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/MyExecutable.dir/main.cpp.o.requires

CMakeFiles/MyExecutable.dir/main.cpp.o.provides: CMakeFiles/MyExecutable.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/MyExecutable.dir/build.make CMakeFiles/MyExecutable.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/MyExecutable.dir/main.cpp.o.provides

CMakeFiles/MyExecutable.dir/main.cpp.o.provides.build: CMakeFiles/MyExecutable.dir/main.cpp.o


# Object files for target MyExecutable
MyExecutable_OBJECTS = \
"CMakeFiles/MyExecutable.dir/main.cpp.o"

# External object files for target MyExecutable
MyExecutable_EXTERNAL_OBJECTS =

MyExecutable: CMakeFiles/MyExecutable.dir/main.cpp.o
MyExecutable: CMakeFiles/MyExecutable.dir/build.make
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_log.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_log_setup.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_filesystem.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_thread.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_date_time.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_regex.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_chrono.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_system.so
MyExecutable: /usr/lib/x86_64-linux-gnu/libboost_atomic.so
MyExecutable: CMakeFiles/MyExecutable.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/project/log/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable MyExecutable"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/MyExecutable.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/MyExecutable.dir/build: MyExecutable

.PHONY : CMakeFiles/MyExecutable.dir/build

CMakeFiles/MyExecutable.dir/requires: CMakeFiles/MyExecutable.dir/main.cpp.o.requires

.PHONY : CMakeFiles/MyExecutable.dir/requires

CMakeFiles/MyExecutable.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/MyExecutable.dir/cmake_clean.cmake
.PHONY : CMakeFiles/MyExecutable.dir/clean

CMakeFiles/MyExecutable.dir/depend:
	cd /project/log/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /project/log /project/log /project/log/build /project/log/build /project/log/build/CMakeFiles/MyExecutable.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/MyExecutable.dir/depend

