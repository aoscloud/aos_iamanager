module github.com/aoscloud/aos_iamanager

go 1.21

replace github.com/ThalesIgnite/crypto11 => github.com/aoscloud/crypto11 v1.0.3-0.20220217163524-ddd0ace39e6f

require (
	github.com/ThalesIgnite/crypto11 v0.0.0-00010101000000-000000000000
	github.com/aoscloud/aos_common v0.0.0-20231127154544-f0075875ceac
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/dchest/uniuri v1.2.0
	github.com/golang/protobuf v1.5.3
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
	github.com/google/uuid v1.4.0
	github.com/gorilla/websocket v1.5.1
	github.com/mattn/go-sqlite3 v1.14.18
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/crypto v0.15.0
	google.golang.org/grpc v1.59.0
)

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
