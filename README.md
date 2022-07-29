# wintoken

Windows Token Manipulation in Go

Wintoken abstracts away windows token manipulation functions with functions you are more likely to use. The library exposes easy-to-use functions to steal tokens, enable/disable privileges, and grab interactive and linked tokens.

Read more here: [Manipulating Windows Tokens With Go](https://fourcore.io/blogs/manipulating-windows-tokens-with-golang)

## Install

- Go
  - Requires Go to be installed on system. Tested on Go1.16+.
  - `go get github.com/fourcorelabs/wintoken`

## Usage
- To steal a token from a process, you can use OpenProcessToken and supply the PID and the type of token that you want

```go
package main

import (
	"os/exec"
	"syscall"

	"github.com/fourcorelabs/wintoken"
)

func main() {
	token, err := wintoken.OpenProcessToken(1234, wintoken.TokenPrimary) //pass 0 for own process
	if err != nil {
		panic(err)
	}
	defer token.Close()

	//Now you can use the token anywhere you would like
	cmd := exec.Command("/path/to/binary")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token.Token())}
}
```

- If you want the elevated interactive token for the currently logged in user, you can call GetInteractiveToken with TokenLinked as parameter

```go
package main

import (
	"os/exec"
	"syscall"

	"github.com/fourcorelabs/wintoken"
)

func main() {
	//You can get an interactive token(if you are running as a service)
	//and specify that you want the linked token(elevated) in the same line
	token, err := wintoken.GetInteractiveToken(wintoken.TokenLinked)
	if err != nil {
		panic(err)
	}
	defer token.Close()

	//Now you can use the token anywhere you would like
	cmd := exec.Command("/path/to/binary")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token.Token())}
}
```

- Once you have a token, you can query information from this token such as its privileges, integrity levels, associated user details, etc.

```go
package main

import (
	"fmt"

	"github.com/fourcorelabs/wintoken"
)

func main() {
	token, err := wintoken.OpenProcessToken(1234, wintoken.TokenPrimary)
	if err != nil {
		panic(err)
	}
	defer token.Close()

	fmt.Println(token.GetPrivileges())
	fmt.Println(token.GetIntegrityLevel())
	fmt.Println(token.UserDetails())
}
```

- You can Enable, Disable, and Remove privileges in a simple manner

```go
package main

import(
	"github.com/fourcorelabs/wintoken"
)

func main(){
	token, err := wintoken.OpenProcessToken(1234, wintoken.TokenPrimary)
	if err != nil {
		panic(err)
	}
	//Enable, Disable, or Remove privileges in one line
	token.EnableAllPrivileges()
	token.DisableTokenPrivileges([]string{"SeShutdownPrivilege", "SeTimeZonePrivilege"})
	token.RemoveTokenPrivilege("SeUndockPrivilege")
}
```
