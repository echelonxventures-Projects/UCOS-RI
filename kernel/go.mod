module ucos.dev/ri/kernel

go 1.25

require (
	github.com/jackc/pgx/v5 v5.7.2
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.1
	ucos.dev/ri/authn v0.0.0
	ucos.dev/ri/contextruntime v0.0.0
	ucos.dev/ri/pdp v0.0.0
)

require (
	cel.dev/expr v0.18.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/google/cel-go v0.22.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20230515195305-f3d0a9c9a5cc // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace ucos.dev/ri/contextruntime => ../platform/context-runtime/go

replace ucos.dev/ri/pdp => ../platform/pdp/go

replace ucos.dev/ri/authn => ../platform/authn/go
