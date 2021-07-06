module aos_iamanager

go 1.14

require (
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/golang/protobuf v1.4.3
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.2.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/websocket v1.4.1
	github.com/mattn/go-sqlite3 v1.14.2
	github.com/miekg/pkcs11 v1.0.3
	github.com/sirupsen/logrus v1.7.0
	gitpct.epam.com/epmd-aepr/aos_common v0.0.0-20210524132411-918d2305a9a0
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	google.golang.org/grpc v1.33.1
	google.golang.org/protobuf v1.25.0 // indirect
)

replace (
	github.com/ThalesIgnite/crypto1 v1.2.4 => github.com/xen-troops/crypto11 v1.2.4
)
