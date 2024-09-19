# Compiler and linker configurations
CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -pedantic -std=c++20
LDFLAGS = -lpcap

# Define all cpp files as sources
SOURCES = main.cpp argument_parser.cpp packet_capturing.cpp packet_processing.cpp
# Define all object files based on sources
OBJECTS = $(SOURCES:.cpp=.o)
# Define the executable file name
EXECUTABLE = dns-monitor

# The first target is the one that is executed when you run make without args
all: $(SOURCES) $(EXECUTABLE)

# This will link the executable
$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# This will compile the source files into object files
.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up the compilation
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
