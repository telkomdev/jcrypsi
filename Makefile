.PHONY : build clean format test

build:
	mvn clean package

test:
	mvn test