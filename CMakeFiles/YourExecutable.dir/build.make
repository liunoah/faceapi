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
CMAKE_SOURCE_DIR = /project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /project

# Include any dependencies generated for this target.
include CMakeFiles/YourExecutable.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/YourExecutable.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/YourExecutable.dir/flags.make

CMakeFiles/YourExecutable.dir/main.cpp.o: CMakeFiles/YourExecutable.dir/flags.make
CMakeFiles/YourExecutable.dir/main.cpp.o: main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/project/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/YourExecutable.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/YourExecutable.dir/main.cpp.o -c /project/main.cpp

CMakeFiles/YourExecutable.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/YourExecutable.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /project/main.cpp > CMakeFiles/YourExecutable.dir/main.cpp.i

CMakeFiles/YourExecutable.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/YourExecutable.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /project/main.cpp -o CMakeFiles/YourExecutable.dir/main.cpp.s

CMakeFiles/YourExecutable.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/YourExecutable.dir/main.cpp.o.requires

CMakeFiles/YourExecutable.dir/main.cpp.o.provides: CMakeFiles/YourExecutable.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/YourExecutable.dir/build.make CMakeFiles/YourExecutable.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/YourExecutable.dir/main.cpp.o.provides

CMakeFiles/YourExecutable.dir/main.cpp.o.provides.build: CMakeFiles/YourExecutable.dir/main.cpp.o


# Object files for target YourExecutable
YourExecutable_OBJECTS = \
"CMakeFiles/YourExecutable.dir/main.cpp.o"

# External object files for target YourExecutable
YourExecutable_EXTERNAL_OBJECTS =

YourExecutable: CMakeFiles/YourExecutable.dir/main.cpp.o
YourExecutable: CMakeFiles/YourExecutable.dir/build.make
YourExecutable: CMakeFiles/YourExecutable.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/project/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable YourExecutable"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/YourExecutable.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/YourExecutable.dir/build: YourExecutable

.PHONY : CMakeFiles/YourExecutable.dir/build

CMakeFiles/YourExecutable.dir/requires: CMakeFiles/YourExecutable.dir/main.cpp.o.requires

.PHONY : CMakeFiles/YourExecutable.dir/requires

CMakeFiles/YourExecutable.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/YourExecutable.dir/cmake_clean.cmake
.PHONY : CMakeFiles/YourExecutable.dir/clean

CMakeFiles/YourExecutable.dir/depend:
	cd /project && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /project /project /project /project /project/CMakeFiles/YourExecutable.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/YourExecutable.dir/depend

