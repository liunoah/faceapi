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
CMAKE_SOURCE_DIR = /project/base64

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /project/base64/build

# Include any dependencies generated for this target.
include CMakeFiles/testProject.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/testProject.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/testProject.dir/flags.make

CMakeFiles/testProject.dir/test.cpp.o: CMakeFiles/testProject.dir/flags.make
CMakeFiles/testProject.dir/test.cpp.o: ../test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/project/base64/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/testProject.dir/test.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/testProject.dir/test.cpp.o -c /project/base64/test.cpp

CMakeFiles/testProject.dir/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testProject.dir/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /project/base64/test.cpp > CMakeFiles/testProject.dir/test.cpp.i

CMakeFiles/testProject.dir/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testProject.dir/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /project/base64/test.cpp -o CMakeFiles/testProject.dir/test.cpp.s

CMakeFiles/testProject.dir/test.cpp.o.requires:

.PHONY : CMakeFiles/testProject.dir/test.cpp.o.requires

CMakeFiles/testProject.dir/test.cpp.o.provides: CMakeFiles/testProject.dir/test.cpp.o.requires
	$(MAKE) -f CMakeFiles/testProject.dir/build.make CMakeFiles/testProject.dir/test.cpp.o.provides.build
.PHONY : CMakeFiles/testProject.dir/test.cpp.o.provides

CMakeFiles/testProject.dir/test.cpp.o.provides.build: CMakeFiles/testProject.dir/test.cpp.o


# Object files for target testProject
testProject_OBJECTS = \
"CMakeFiles/testProject.dir/test.cpp.o"

# External object files for target testProject
testProject_EXTERNAL_OBJECTS =

testProject: CMakeFiles/testProject.dir/test.cpp.o
testProject: CMakeFiles/testProject.dir/build.make
testProject: /usr/lib/x86_64-linux-gnu/libcrypto.so
testProject: /usr/lib/x86_64-linux-gnu/libboost_system.so
testProject: /usr/lib/x86_64-linux-gnu/libboost_date_time.so
testProject: CMakeFiles/testProject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/project/base64/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable testProject"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/testProject.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/testProject.dir/build: testProject

.PHONY : CMakeFiles/testProject.dir/build

CMakeFiles/testProject.dir/requires: CMakeFiles/testProject.dir/test.cpp.o.requires

.PHONY : CMakeFiles/testProject.dir/requires

CMakeFiles/testProject.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/testProject.dir/cmake_clean.cmake
.PHONY : CMakeFiles/testProject.dir/clean

CMakeFiles/testProject.dir/depend:
	cd /project/base64/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /project/base64 /project/base64 /project/base64/build /project/base64/build /project/base64/build/CMakeFiles/testProject.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/testProject.dir/depend

