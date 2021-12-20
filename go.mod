module aos_iamanager

go 1.14

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/aoscloud/aos_common v0.0.0-20211220123623-d23b9d38e838
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.2.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.4.2
	github.com/mattn/go-sqlite3 v1.14.9
	github.com/miekg/pkcs11 v1.0.3
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/grpc v1.41.0
)

replace github.com/ThalesIgnite/crypto1 v1.2.4 => github.com/xen-troops/crypto11 v1.2.4
