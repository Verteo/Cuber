all:
	g++ -Wall -Wextra -Wno-unused-result -march=native -O2 -Iinclude cuber.cpp -o cuber -lcrypto
