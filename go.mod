module github.com/aoscloud/aos_iamanager

go 1.18

replace github.com/ThalesIgnite/crypto11 => github.com/aoscloud/crypto11 v1.0.3-0.20220217163524-ddd0ace39e6f

require (
	github.com/ThalesIgnite/crypto11 v0.0.0-00010101000000-000000000000
	github.com/aoscloud/aos_common v0.0.0-20230207151223-d8ba3fd728c5
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/dchest/uniuri v1.2.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.10
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.5.0
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/miekg/pkcs11 v1.0.3
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/crypto v0.14.0
	google.golang.org/grpc v1.52.3
)

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20221118155620-16455021b5e6 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
