package main

func main() {
	err := RunServer(3001)
	if err != nil {
		panic(err)
	}
}
