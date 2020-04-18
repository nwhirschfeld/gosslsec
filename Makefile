all:
	cd parseciphersuites && go run *.go > ../ciphersuitenamemap.go
	go build -o gosslsec *.go