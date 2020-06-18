all: main

main:
	g++ main.cpp Modules/AES.cpp Modules/DES.cpp Modules/RC2.cpp Modules/RC5.cpp Modules/RC6.cpp Modules/GOST.cpp Modules/BLOW.cpp Modules/TWO.cpp Modules/SERP.cpp Modules/CAM.cpp -lcrypto++

clean:
	rm a.out
