module github.com/aoscloud/aos_iamanager

go 1.18

replace github.com/ThalesIgnite/crypto11 => github.com/aoscloud/crypto11 v1.0.3-0.20220217163524-ddd0ace39e6f

require (
	github.com/ThalesIgnite/crypto11 v0.0.0-00010101000000-000000000000
	github.com/aoscloud/aos_common v0.0.0-20221221083939-9cf778bc1245
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.2.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/websocket v1.5.0
	github.com/mattn/go-sqlite3 v1.14.13
	github.com/miekg/pkcs11 v1.0.3
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	google.golang.org/grpc v1.46.2
)

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/sys v0.0.0-20220317061510-51cd9980dadf // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220314164441-57ef72a4c106 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)
