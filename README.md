
# MORF - Mobile Reconnaissance Framework 

Mobile Reconnaissance Framework is a powerful, lightweight and platform-independent offensive mobile security tool designed to help hackers and developers identify and address sensitive information within mobile applications. It is like a swiss army knife for mobile application security, as it uses heuristics-based techniques to search through the codebase, creating a comprehensive repository of sensitive information it finds. This makes it easy to identify and address any potential sensitive data leak.

One of the prominent features of MORF is its ability to automatically detect and extract sensitive information from various sources, including source code, resource files, and native libraries. It also collects a large amount of metadata from the application, which can be used to create data science models that can predict and detect potential security threats. MORF also looks into all previous versions of the application, bringing transparency to the security posture of the application.

The tool boasts a user-friendly interface and an easy-to-use reporting system that makes it simple for hackers and security professionals to review and address any identified issues. With MORF, you can know that your mobile application's security is in good hands.

Overall, MORF is a swiss army knife for offensive mobile application security, as it saves a lot of time, increases efficiency, enables a data-driven approach, allows for transparency in the security posture of the application by looking into all previous versions, and minimizes the risk of data breaches related to sensitive information, all this by using heuristics-based techniques.


## Architecture

![MORF Architecture drawio (2)](https://github.com/amrudesh1/MORF/assets/20198748/f5bcdbbf-68ea-41bc-9c12-3f6d07e9049d)


## Presentations / Conferences

- [BlackHat Asia 2023 - Aresenal](https://www.blackhat.com/asia-23/arsenal/schedule/#morf---mobile-reconnaissance-framework-31292) 
## Demo

![ezgif com-video-to-gif](https://github.com/amrudesh1/MORF/assets/20198748/1fec6d18-e279-4a8a-b63c-01a1d66c20a2)


## Environment Variables

To run this project, you will need to add the following environment variables to your environment variables/

`DATABASE_URL`


## Installation

### Installation Guide for a Golang Project

#### Step 1: Install Go

First, you need to install Go on your system. Visit the official Go downloads page at `https://golang.org/dl/` to download the appropriate binary release for your system.

After downloading the file, open your terminal or command prompt, navigate to the download directory and run the installer.

You can verify your installation by running:

``` bash
go version
```

This should display the installed version of Go.

#### Step 2: Set up your Go workspace

In Go, it is typical to have a single workspace which contains the source files of all your Go programs and libraries.

A workspace is a directory hierarchy with three directories at its root:

- `src` contains Go source files organized into packages (one package per directory)
- `bin` contains executable commands
- `pkg` contains Go package archives

By convention, the workspace directory is named `go`.

#### Step 3: Set the GOPATH environment variable

The `GOPATH` environment variable specifies the location of your workspace. If `GOPATH` is not set, it is assumed to be `$HOME/go` on Unix systems and `%USERPROFILE%\\go` on Windows.

On Unix systems, you can set the `GOPATH` environment variable by adding the following line to your `~/.bashrc` or `~/.bash_profile` file:

```bash
export GOPATH=$HOME/go
```

On Windows, you can set it via "Advanced System Settings" -> "Environment Variables".

#### Step 4: Download the Go project

Let's say you have a Go project on GitHub that you want to install. You can use the `go get` command followed by the package source:

```bash
go get github.com/amrudesh1/morf
```

This command does two things: it downloads the source code of the package and also installs the package.

#### Step 5: Build and Run the Go project

Navigate to the project directory within your workspace, which should be something like `$GOPATH/src/github.com/amrudesh1/morf`.

Then, you can build and run the project with:

```bash
go build
./morf --help
```

### Docker Installation

#### Step 1: Install Docker

First, you need to have Docker installed on your machine. If you haven't installed Docker yet, you can download it from the official Docker website at `https://www.docker.com/get-started` and follow the instructions for your operating system.

#### Step 2: Build the Docker image

Open your terminal or command prompt, navigate to the directory containing the Dockerfile, and build the Docker image by running:

```bash 
docker build -t morf .

```

This command builds a Docker image from the Dockerfile and tags (-t) the image as `morf`. The dot at the end of the command specifies that the Dockerfile is in the current directory.


#### Step 3: Run the Docker container

After the Docker image has been built, you can run the Docker container with the following command:

```bash
docker run -p 8888:8888 -e DATABASE_URL="root@tcp(host.docker.internal:3306)/Secrets?charset=utf8mb4&parseTime=True&loc=Local"  -it secscan
```

You can replace the ```host.docker.internal``` with a database ip address if you are planning to host MORF. 





## Authors

- [@amrudesh1](https://www.github.com/amrudesh1)
- [@abhi-r3v0](https://www.github.com/abhi-r3v0)
- [@himanshudas](https://github.com/himanshudas)


## Acknowledgements

 - [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db) - Database Used by MORF for finding secrets in the application.
