## jcrypsi (crypsi for Java Virtual Machine)

Custom crypto utility for Java Virtual Machine

[![JCrypsi CI](https://github.com/telkomdev/jcrypsi/actions/workflows/ci.yml/badge.svg)](https://github.com/telkomdev/jcrypsi/actions/workflows/ci.yml)

### jcrypsi is compatible with each other with the following libraries
- NodeJs https://github.com/telkomdev/crypsi
- Python https://github.com/telkomdev/pycrypsi
- Golang https://github.com/telkomdev/go-crypsi
- C# (.NET) https://github.com/telkomdev/NetCrypsi
- Javascript (React and Browser) https://github.com/telkomdev/crypsi.js

### Features
- Asymmetric encryption with RSA
- Generate RSA private and public key
- Digital Signature with RSA private and public key using PSS
- Symmetric encryption with AES
- Message authentication code with HMAC
- Generate Hash with Common DIGEST Algorithm

### Build and Test

Requirements:
- Java JDK 8 or Higher https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html


for build tools you can choose between `Maven` or `Gradle`
- Maven https://maven.apache.org/download.cgi
- Gradle https://gradle.org/install/

Running `unit test`
- with Maven
```shell
$ mvn test
```

- with Gradle
```shell
$ gradle clean
$ gradle test
```

Running `example snippet application`
- Build with Maven
```shell
$ mvn clean package
$ java -jar target/app.jar 
```

- Build with Gradle
```shell
$ gradle fatJar 
$ java -jar build/libs/app-1.0-SNAPSHOT.jar
```

### Add `jcrypsi` to your project
TODO